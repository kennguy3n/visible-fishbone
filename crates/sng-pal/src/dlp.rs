//! DLP channel interceptors — the platform-abstraction-layer side
//! of endpoint Data Loss Prevention.
//!
//! `sng-dlp` defines *what* a content event is
//! ([`sng_dlp::ContentEvent`]) and the consumer contract
//! ([`sng_dlp::ChannelInterceptor`]); this module provides the
//! per-OS *sources* that observe those events off the live system
//! and the [`sng_dlp::engine::DlpEngine`] then rules on them.
//!
//! # Backends
//!
//! The flagship cross-platform primitive is [`SensitiveDirWatcher`]:
//! a bounded, allocation-conscious directory watcher that detects
//! file writes by polling watched roots and comparing mtimes
//! against a per-file watermark. The three desktop OSes each expose
//! a richer edge-triggered kernel facility — the Windows USN change
//! journal, macOS FSEvents, Linux inotify — and the per-OS structs
//! below document the upgrade path; the polling watcher is the
//! portable, dependency-free implementation that runs everywhere
//! (including CI, which is headless Linux) with identical observable
//! behaviour. This mirrors how [`crate::posture`] derives Linux
//! posture from `/proc` + `/sys` reads rather than pulling a heavy
//! syscall crate.
//!
//! Channels that are inherently a userspace coordination rather than
//! a filesystem event — browser upload, which is mediated by the SWG
//! — are modelled as an in-process bridge ([`BrowserUploadBridge`]).
//!
//! # Redaction
//!
//! These sources are the *only* place raw content exists: they read
//! the bytes that crossed a channel into a [`sng_dlp::ContentEvent`]
//! so the engine can classify them. Per the crate-wide redaction
//! invariant the engine then emits metadata only — the raw bytes
//! never outlive the inspection call.

use async_trait::async_trait;
use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

/// Default ceiling on bytes read from any single file into a content
/// event. Keeps a runaway multi-gigabyte file from blowing the
/// agent's resident-memory budget; the classifier applies its own
/// (smaller) scan ceiling on top.
pub const DEFAULT_MAX_FILE_BYTES: usize = 1024 * 1024;

/// Default poll cadence for [`SensitiveDirWatcher`].
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum directory depth [`SensitiveDirWatcher::scan`] descends.
const MAX_WALK_DEPTH: usize = 8;

/// Maximum number of files examined in one scan pass — bounds the
/// worst-case cost of a single poll on a large tree.
const MAX_FILES_PER_SCAN: usize = 4096;

/// Map a path's extension to a declared MIME type for the event
/// metadata. Best-effort; unknown extensions yield `None`.
#[must_use]
pub fn mime_for_path(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "rtf" => "application/rtf",
        "zip" => "application/zip",
        _ => return None,
    };
    Some(mime)
}

/// A bounded, polling directory watcher.
///
/// Constructed over a set of watched roots and a [`DlpChannel`] to
/// tag emitted events with. Each [`Self::scan`] pass walks the roots
/// (depth- and count-bounded), and for every regular file whose
/// modification time is newer than the last observation, reads up to
/// [`Self::max_file_bytes`] of its content into a queued
/// [`ContentEvent`]. The watermark map makes re-scans idempotent: an
/// unchanged file is reported once, a rewritten file is reported
/// again.
#[derive(Debug)]
pub struct SensitiveDirWatcher {
    channel: DlpChannel,
    dirs: Mutex<Vec<PathBuf>>,
    seen: Mutex<HashMap<PathBuf, SystemTime>>,
    buffer: Mutex<VecDeque<ContentEvent>>,
    max_file_bytes: usize,
    poll_interval: Duration,
    closed: AtomicBool,
    /// When set, the first [`scan`](Self::scan) only records the
    /// watermark for files that already exist and queues no events, so
    /// startup does not re-report every pre-existing file as a fresh
    /// write. See [`warm_started`](Self::warm_started).
    warm_start: bool,
    primed: AtomicBool,
}

impl SensitiveDirWatcher {
    /// Watch `dirs`, tagging events with `channel`.
    #[must_use]
    pub fn new(channel: DlpChannel, dirs: Vec<PathBuf>) -> Self {
        Self {
            channel,
            dirs: Mutex::new(dirs),
            seen: Mutex::new(HashMap::new()),
            buffer: Mutex::new(VecDeque::new()),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            poll_interval: DEFAULT_POLL_INTERVAL,
            closed: AtomicBool::new(false),
            warm_start: false,
            primed: AtomicBool::new(false),
        }
    }

    /// Prime the watermark on the first scan instead of reporting every
    /// pre-existing file as a new write. Use this for monitors pointed
    /// at long-lived sensitive directories (file-write), where a burst
    /// of events for files that predate the agent would be spurious;
    /// only writes that happen after start-up are then reported.
    #[must_use]
    pub fn warm_started(mut self) -> Self {
        self.warm_start = true;
        self
    }

    /// Override the per-file read ceiling.
    #[must_use]
    pub fn with_max_file_bytes(mut self, max: usize) -> Self {
        self.max_file_bytes = max;
        self
    }

    /// Override the poll cadence.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// The poll cadence.
    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Replace the watched roots (used by the USB monitor as
    /// removable volumes are mounted / unmounted).
    pub fn set_dirs(&self, dirs: Vec<PathBuf>) {
        *lock(&self.dirs) = dirs;
    }

    /// Signal that the source has been torn down. A subsequent
    /// [`ChannelInterceptor::next_event`] drains any buffered events
    /// then returns `Ok(None)`.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Pop one buffered event, if any.
    pub fn try_pop(&self) -> Option<ContentEvent> {
        lock(&self.buffer).pop_front()
    }

    /// Run one scan pass, queueing an event per newly-written file.
    /// Returns the number of events queued.
    ///
    /// When [`warm_started`](Self::warm_started) is set, the first pass
    /// only records the current watermark and queues nothing.
    pub fn scan(&self) -> usize {
        if self.warm_start && !self.primed.swap(true, Ordering::SeqCst) {
            self.walk(true);
            return 0;
        }
        self.walk(false)
    }

    /// Record the current mtime of every watched file without queuing
    /// events. Returns the number of files primed. Exposed for callers
    /// that want to prime explicitly (e.g. after remounting a volume).
    pub fn warm_up(&self) -> usize {
        self.primed.store(true, Ordering::SeqCst);
        self.walk(true)
    }

    /// Shared directory walk. With `record_only`, new files only update
    /// the watermark (no read, no event); otherwise each new write is
    /// read into a queued event. Returns the count of files acted on
    /// (events queued, or watermarks recorded in `record_only`).
    ///
    /// When a pass completes cleanly — every watched directory was
    /// readable and the per-scan file cap was not hit — the watermark
    /// map is pruned to the set of files observed this pass, so entries
    /// for deleted files do not accumulate for a long-lived agent on a
    /// high-churn directory. A truncated or partially-failed pass skips
    /// the prune so a transiently-unreadable directory cannot cause its
    /// files to be re-reported as fresh writes on the next scan.
    fn walk(&self, record_only: bool) -> usize {
        let dirs = lock(&self.dirs).clone();
        let mut stack: Vec<(PathBuf, usize)> = dirs.into_iter().map(|d| (d, 0)).collect();
        let mut examined = 0usize;
        let mut queued = 0usize;
        let mut observed: HashSet<PathBuf> = HashSet::new();
        let mut complete = true;

        while let Some((dir, depth)) = stack.pop() {
            if examined >= MAX_FILES_PER_SCAN {
                complete = false;
                break;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                complete = false;
                continue;
            };
            for entry in entries.flatten() {
                if examined >= MAX_FILES_PER_SCAN {
                    complete = false;
                    break;
                }
                let path = entry.path();
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.is_dir() {
                    if depth < MAX_WALK_DEPTH {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                if !meta.is_file() {
                    continue;
                }
                examined += 1;
                let Ok(modified) = meta.modified() else {
                    continue;
                };
                observed.insert(path.clone());
                if !self.is_new_write(&path, modified) {
                    continue;
                }
                if record_only {
                    queued += 1;
                    continue;
                }
                if let Some(event) = self.read_event(&path) {
                    lock(&self.buffer).push_back(event);
                    queued += 1;
                }
            }
        }
        if complete {
            self.prune_unseen(&observed);
        }
        queued
    }

    /// Drop watermarks for files that no longer exist. Called only after
    /// a complete walk, so `observed` is the full live file set and any
    /// watermark not in it is for a deleted (or moved) file.
    fn prune_unseen(&self, observed: &HashSet<PathBuf>) {
        let mut seen = lock(&self.seen);
        if seen.len() == observed.len() {
            return;
        }
        seen.retain(|path, _| observed.contains(path));
    }

    /// Number of watermarks currently retained. Test-only introspection.
    #[cfg(test)]
    fn watermark_count(&self) -> usize {
        lock(&self.seen).len()
    }

    /// Whether `path` at `modified` is a write we have not reported.
    /// Updates the watermark as a side effect.
    fn is_new_write(&self, path: &Path, modified: SystemTime) -> bool {
        let mut seen = lock(&self.seen);
        match seen.get(path) {
            Some(&prev) if prev >= modified => false,
            _ => {
                seen.insert(path.to_path_buf(), modified);
                true
            }
        }
    }

    /// Read up to `max_file_bytes` of `path` into a content event.
    fn read_event(&self, path: &Path) -> Option<ContentEvent> {
        let file = std::fs::File::open(path).ok()?;
        let cap = u64::try_from(self.max_file_bytes).unwrap_or(u64::MAX);
        let mut buf = Vec::new();
        if file.take(cap).read_to_end(&mut buf).is_err() {
            return None;
        }
        let metadata = ContentMetadata {
            filename: path
                .file_name()
                .and_then(|n| n.to_str())
                .map(ToOwned::to_owned),
            content_type: mime_for_path(path).map(ToOwned::to_owned),
            source: path
                .parent()
                .and_then(|p| p.to_str())
                .map(ToOwned::to_owned),
            mip_labels: Vec::new(),
        };
        Some(ContentEvent {
            channel: self.channel,
            content: buf,
            metadata,
        })
    }
}

#[async_trait]
impl ChannelInterceptor for SensitiveDirWatcher {
    fn channel(&self) -> DlpChannel {
        self.channel
    }

    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        loop {
            if let Some(event) = self.try_pop() {
                return Ok(Some(event));
            }
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            if self.scan() == 0 {
                if self.closed.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                tokio::time::sleep(self.poll_interval).await;
            }
        }
    }
}

/// In-process bridge for the browser-upload channel.
///
/// Browser upload inspection is not a filesystem event: the SWG
/// (`sng-swg`) already sits in the upload path and holds the request
/// body. Rather than re-hook the browser, the SWG hands the body to
/// this bridge, which surfaces it to the DLP engine as a
/// [`DlpChannel::BrowserUpload`] event. The two components are
/// in-process in the agent, so the hand-off is a queue push.
#[derive(Debug, Default)]
pub struct BrowserUploadBridge {
    buffer: Mutex<VecDeque<ContentEvent>>,
    closed: AtomicBool,
}

impl BrowserUploadBridge {
    /// A new, empty bridge.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit an upload body for inspection. `filename` /
    /// `content_type` come from the multipart part headers the SWG
    /// already parsed.
    pub fn submit(&self, content: Vec<u8>, filename: Option<String>, content_type: Option<String>) {
        let metadata = ContentMetadata {
            filename,
            content_type,
            source: Some("browser_upload".to_owned()),
            mip_labels: Vec::new(),
        };
        lock(&self.buffer).push_back(ContentEvent {
            channel: DlpChannel::BrowserUpload,
            content,
            metadata,
        });
    }

    /// Tear the bridge down; pending events still drain.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl ChannelInterceptor for BrowserUploadBridge {
    fn channel(&self) -> DlpChannel {
        DlpChannel::BrowserUpload
    }

    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        loop {
            if let Some(event) = lock(&self.buffer).pop_front() {
                return Ok(Some(event));
            }
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// A mount-table entry parsed from `/proc/mounts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// Backing device (e.g. `/dev/sdb1`).
    pub device: String,
    /// Mount point.
    pub mount_point: PathBuf,
    /// Filesystem type (e.g. `vfat`, `ext4`).
    pub fstype: String,
}

/// A currently-mounted removable volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovableMount {
    /// Backing device.
    pub device: String,
    /// Mount point.
    pub mount_point: PathBuf,
}

/// Parse the contents of `/proc/mounts` (or `/proc/self/mounts`).
///
/// Each line is `device mountpoint fstype options dump pass`;
/// whitespace inside the device / mountpoint fields is octal-escaped
/// (`\040` for space), which this decodes.
#[must_use]
pub fn parse_proc_mounts(contents: &str) -> Vec<MountEntry> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let device = decode_octal(fields.next()?);
            let mount_point = PathBuf::from(decode_octal(fields.next()?));
            let fstype = decode_octal(fields.next()?);
            Some(MountEntry {
                device,
                mount_point,
                fstype,
            })
        })
        .collect()
}

/// Decode the `\NNN` octal escapes the kernel uses in
/// `/proc/mounts` for whitespace and backslashes.
///
/// The kernel escapes each *byte* it cannot emit literally, so a
/// multi-byte UTF-8 path is a run of octal escapes (e.g. `é` →
/// `\303\251`). Decoded bytes are accumulated and interpreted as UTF-8
/// at the end — decoding each escape to a `char` independently would map
/// the raw byte to its Latin-1 code point and corrupt any non-ASCII
/// mount point (which would then fail to match the real directory and
/// silently drop a removable volume from monitoring).
fn decode_octal(field: &str) -> String {
    if !field.contains('\\') {
        return field.to_owned();
    }
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &field[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(digits, 8) {
                out.push(code);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(target_os = "linux")]
pub use linux::{
    LinuxClipboardMonitor, LinuxFileWriteMonitor, LinuxPrintMonitor, LinuxRemovableStorageMonitor,
    LinuxUsbTransferMonitor,
};

#[cfg(target_os = "linux")]
mod linux {
    //! Linux DLP backends.
    //!
    //! * **File write** — [`LinuxFileWriteMonitor`] watches the
    //!   configured sensitive directories. The production upgrade is
    //!   `inotify` (`IN_CLOSE_WRITE`) for edge-triggered delivery;
    //!   the portable [`SensitiveDirWatcher`] poll implementation is
    //!   used here so the agent has no libinotify build dependency.
    //! * **USB transfer** — [`LinuxRemovableStorageMonitor`] reads
    //!   `/proc/mounts` and `/sys/block/<dev>/removable` (the same
    //!   read-only procfs / sysfs surface `udev` consumes) to find
    //!   removable volumes, and [`LinuxUsbTransferMonitor`] scans the
    //!   files copied onto them.
    //! * **Print** — [`LinuxPrintMonitor`] watches the CUPS spool
    //!   directory (`/var/spool/cups`) for queued job data.
    //! * **Clipboard** — [`LinuxClipboardMonitor`] reads the
    //!   selection via `wl-paste` (Wayland) or `xclip` (X11); on a
    //!   headless host with no display it reports
    //!   [`ChannelError::Unavailable`].

    use super::{DEFAULT_POLL_INTERVAL, MountEntry, RemovableMount, SensitiveDirWatcher};
    use async_trait::async_trait;
    use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Default directories an endpoint watches for sensitive-file
    /// writes when the policy does not override them.
    fn default_sensitive_dirs() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            dirs.push(home.join("Documents"));
            dirs.push(home.join("Downloads"));
            dirs.push(home.join("Desktop"));
        }
        dirs.push(PathBuf::from("/tmp"));
        dirs
    }

    /// Linux file-write monitor. Newtype over [`SensitiveDirWatcher`]
    /// fixed to [`DlpChannel::FileWrite`].
    #[derive(Debug)]
    pub struct LinuxFileWriteMonitor {
        watcher: SensitiveDirWatcher,
    }

    impl LinuxFileWriteMonitor {
        /// Watch `dirs` (empty → the default sensitive set).
        #[must_use]
        pub fn new(dirs: Vec<PathBuf>) -> Self {
            let dirs = if dirs.is_empty() {
                default_sensitive_dirs()
            } else {
                dirs
            };
            Self {
                // Warm-start: don't re-report files that predate the
                // agent; only writes after start-up are sensitive here.
                watcher: SensitiveDirWatcher::new(DlpChannel::FileWrite, dirs).warm_started(),
            }
        }

        /// The underlying watcher (for poll-interval / byte-ceiling
        /// tuning).
        #[must_use]
        pub fn watcher(&self) -> &SensitiveDirWatcher {
            &self.watcher
        }
    }

    #[async_trait]
    impl ChannelInterceptor for LinuxFileWriteMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::FileWrite
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            self.watcher.next_event().await
        }
    }

    /// Linux print monitor — watches the CUPS spool directory.
    #[derive(Debug)]
    pub struct LinuxPrintMonitor {
        watcher: SensitiveDirWatcher,
    }

    impl LinuxPrintMonitor {
        /// Watch `spool_dir` (default `/var/spool/cups`).
        #[must_use]
        pub fn new(spool_dir: Option<PathBuf>) -> Self {
            let dir = spool_dir.unwrap_or_else(|| PathBuf::from("/var/spool/cups"));
            Self {
                watcher: SensitiveDirWatcher::new(DlpChannel::Print, vec![dir]),
            }
        }
    }

    #[async_trait]
    impl ChannelInterceptor for LinuxPrintMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::Print
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            self.watcher.next_event().await
        }
    }

    /// Detects removable volumes from `/proc/mounts` +
    /// `/sys/block/<dev>/removable`.
    #[derive(Clone, Debug)]
    pub struct LinuxRemovableStorageMonitor {
        proc_mounts: PathBuf,
        sys_block: PathBuf,
    }

    impl Default for LinuxRemovableStorageMonitor {
        fn default() -> Self {
            Self {
                proc_mounts: PathBuf::from("/proc/mounts"),
                sys_block: PathBuf::from("/sys/block"),
            }
        }
    }

    impl LinuxRemovableStorageMonitor {
        /// Test constructor with injected procfs / sysfs roots.
        #[must_use]
        pub fn with_roots(proc_mounts: PathBuf, sys_block: PathBuf) -> Self {
            Self {
                proc_mounts,
                sys_block,
            }
        }

        /// Currently-mounted removable volumes.
        #[must_use]
        pub fn removable_mounts(&self) -> Vec<RemovableMount> {
            let contents = std::fs::read_to_string(&self.proc_mounts).unwrap_or_default();
            super::parse_proc_mounts(&contents)
                .into_iter()
                .filter(|m: &MountEntry| m.device.starts_with("/dev/"))
                .filter(|m| self.is_removable(&m.device))
                .map(|m| RemovableMount {
                    device: m.device,
                    mount_point: m.mount_point,
                })
                .collect()
        }

        /// Whether `device`'s backing disk is flagged removable.
        fn is_removable(&self, device: &str) -> bool {
            let name = device.trim_start_matches("/dev/");
            let disk = self.disk_of(name);
            let flag = self.sys_block.join(&disk).join("removable");
            std::fs::read_to_string(flag).is_ok_and(|s| s.trim() == "1")
        }

        /// Resolve a partition node name to its parent disk name
        /// (`sdb1` → `sdb`, `nvme0n1p2` → `nvme0n1`).
        fn disk_of(&self, part: &str) -> String {
            let mut cand = part.to_owned();
            for _ in 0..4 {
                if self.sys_block.join(&cand).exists() {
                    return cand;
                }
                let mut stripped: String = cand
                    .trim_end_matches(|c: char| c.is_ascii_digit())
                    .to_owned();
                if stripped.ends_with('p') {
                    stripped.pop();
                }
                if stripped.is_empty() || stripped == cand {
                    break;
                }
                cand = stripped;
            }
            cand
        }
    }

    /// Watches removable volumes and scans files copied onto them,
    /// emitting [`DlpChannel::UsbTransfer`] events.
    #[derive(Debug)]
    pub struct LinuxUsbTransferMonitor {
        detector: LinuxRemovableStorageMonitor,
        watcher: SensitiveDirWatcher,
        closed: AtomicBool,
    }

    impl LinuxUsbTransferMonitor {
        /// Build a monitor over `detector`.
        #[must_use]
        pub fn new(detector: LinuxRemovableStorageMonitor) -> Self {
            Self {
                detector,
                watcher: SensitiveDirWatcher::new(DlpChannel::UsbTransfer, Vec::new()),
                closed: AtomicBool::new(false),
            }
        }

        /// Stop the monitor.
        pub fn shutdown(&self) {
            self.closed.store(true, Ordering::SeqCst);
            self.watcher.shutdown();
        }

        /// Refresh the watcher's roots to the current removable
        /// mounts and run one scan pass. Returns the events queued.
        fn refresh_and_scan(&self) -> usize {
            let mounts = self.detector.removable_mounts();
            let dirs: Vec<PathBuf> = mounts.into_iter().map(|m| m.mount_point).collect();
            self.watcher.set_dirs(dirs);
            self.watcher.scan()
        }
    }

    #[async_trait]
    impl ChannelInterceptor for LinuxUsbTransferMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::UsbTransfer
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            loop {
                if let Some(event) = self.watcher.try_pop() {
                    return Ok(Some(event));
                }
                if self.closed.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                if self.refresh_and_scan() == 0 {
                    if self.closed.load(Ordering::SeqCst) {
                        return Ok(None);
                    }
                    tokio::time::sleep(DEFAULT_POLL_INTERVAL).await;
                }
            }
        }
    }

    /// Reads the desktop clipboard selection.
    ///
    /// The selection is read on demand each [`next_event`]; the agent
    /// drives this from its display-server change signal rather than
    /// the monitor self-polling. [`shutdown`](Self::shutdown) lets a
    /// consumer that loops to end-of-stream observe the
    /// [`ChannelInterceptor`] contract's `Ok(None)` termination.
    #[derive(Clone, Debug, Default)]
    pub struct LinuxClipboardMonitor {
        closed: Arc<AtomicBool>,
    }

    impl LinuxClipboardMonitor {
        /// A new, open clipboard monitor.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Tear the monitor down; the next [`next_event`] returns
        /// `Ok(None)` per the [`ChannelInterceptor`] contract.
        pub fn shutdown(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }

        /// Read the current clipboard selection, if a display server
        /// and a reader tool are available.
        fn read_selection() -> Result<Vec<u8>, ChannelError> {
            let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
            let x11 = std::env::var_os("DISPLAY").is_some();
            if !wayland && !x11 {
                return Err(ChannelError::Unavailable(
                    "no Wayland or X11 display".to_owned(),
                ));
            }
            let (bin, args): (&str, &[&str]) = if wayland {
                ("wl-paste", &["--no-newline"])
            } else {
                ("xclip", &["-selection", "clipboard", "-o"])
            };
            match Command::new(bin).args(args).output() {
                Ok(out) if out.status.success() => Ok(out.stdout),
                Ok(out) => Err(ChannelError::Init(format!(
                    "{bin} exited with status {}",
                    out.status
                ))),
                Err(e) => Err(ChannelError::Unavailable(format!("{bin} unavailable: {e}"))),
            }
        }
    }

    #[async_trait]
    impl ChannelInterceptor for LinuxClipboardMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::Clipboard
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let content = Self::read_selection()?;
            let metadata = ContentMetadata {
                filename: None,
                content_type: Some("text/plain".to_owned()),
                source: Some("clipboard".to_owned()),
                mip_labels: Vec::new(),
            };
            Ok(Some(ContentEvent {
                channel: DlpChannel::Clipboard,
                content,
                metadata,
            }))
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{MacClipboardMonitor, MacFileWriteMonitor, MacPrintMonitor};

#[cfg(target_os = "macos")]
mod macos {
    //! macOS DLP backends.
    //!
    //! * **File write** — [`MacFileWriteMonitor`] watches the
    //!   configured directories. The production upgrade is the
    //!   FSEvents API (`FSEventStreamCreate`); the portable
    //!   [`SensitiveDirWatcher`] poll implementation is used here.
    //! * **Clipboard** — [`MacClipboardMonitor`] reads
    //!   `NSPasteboard` via `/usr/bin/pbpaste`.
    //! * **Print** — [`MacPrintMonitor`] watches the CUPS spool
    //!   directory.

    use super::SensitiveDirWatcher;
    use async_trait::async_trait;
    use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// macOS file-write monitor.
    #[derive(Debug)]
    pub struct MacFileWriteMonitor {
        watcher: SensitiveDirWatcher,
    }

    impl MacFileWriteMonitor {
        /// Watch `dirs`.
        #[must_use]
        pub fn new(dirs: Vec<PathBuf>) -> Self {
            Self {
                // Warm-start: don't re-report files that predate the
                // agent; only writes after start-up are sensitive here.
                watcher: SensitiveDirWatcher::new(DlpChannel::FileWrite, dirs).warm_started(),
            }
        }
    }

    #[async_trait]
    impl ChannelInterceptor for MacFileWriteMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::FileWrite
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            self.watcher.next_event().await
        }
    }

    /// macOS print monitor — watches the CUPS spool directory.
    #[derive(Debug)]
    pub struct MacPrintMonitor {
        watcher: SensitiveDirWatcher,
    }

    impl MacPrintMonitor {
        /// Watch `spool_dir` (default `/var/spool/cups`).
        #[must_use]
        pub fn new(spool_dir: Option<PathBuf>) -> Self {
            let dir = spool_dir.unwrap_or_else(|| PathBuf::from("/var/spool/cups"));
            Self {
                watcher: SensitiveDirWatcher::new(DlpChannel::Print, vec![dir]),
            }
        }
    }

    #[async_trait]
    impl ChannelInterceptor for MacPrintMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::Print
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            self.watcher.next_event().await
        }
    }

    /// macOS clipboard monitor — reads `NSPasteboard` via `pbpaste`.
    ///
    /// Read on demand each [`next_event`]; [`shutdown`](Self::shutdown)
    /// makes a subsequent call return `Ok(None)` per the
    /// [`ChannelInterceptor`] contract.
    #[derive(Clone, Debug, Default)]
    pub struct MacClipboardMonitor {
        closed: Arc<AtomicBool>,
    }

    impl MacClipboardMonitor {
        /// A new, open clipboard monitor.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Tear the monitor down; the next [`next_event`] returns
        /// `Ok(None)`.
        pub fn shutdown(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ChannelInterceptor for MacClipboardMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::Clipboard
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let output = Command::new("/usr/bin/pbpaste")
                .output()
                .map_err(|e| ChannelError::Unavailable(format!("pbpaste unavailable: {e}")))?;
            if !output.status.success() {
                return Err(ChannelError::Init(format!(
                    "pbpaste exited with status {}",
                    output.status
                )));
            }
            let metadata = ContentMetadata {
                filename: None,
                content_type: Some("text/plain".to_owned()),
                source: Some("clipboard".to_owned()),
                mip_labels: Vec::new(),
            };
            Ok(Some(ContentEvent {
                channel: DlpChannel::Clipboard,
                content: output.stdout,
                metadata,
            }))
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::{WindowsClipboardMonitor, WindowsFileWriteMonitor};

#[cfg(target_os = "windows")]
mod windows_impl {
    //! Windows DLP backends.
    //!
    //! * **File write** — [`WindowsFileWriteMonitor`] watches the
    //!   configured directories. The production upgrade is the USN
    //!   change journal (`FSCTL_QUERY_USN_JOURNAL` +
    //!   `FSCTL_READ_USN_JOURNAL`); the portable
    //!   [`SensitiveDirWatcher`] poll implementation is used here.
    //! * **Clipboard** — [`WindowsClipboardMonitor`] reads the
    //!   clipboard via `Get-Clipboard`; the production upgrade is a
    //!   WMI `Win32_ClipboardData` listener.

    use super::SensitiveDirWatcher;
    use async_trait::async_trait;
    use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Windows file-write monitor.
    #[derive(Debug)]
    pub struct WindowsFileWriteMonitor {
        watcher: SensitiveDirWatcher,
    }

    impl WindowsFileWriteMonitor {
        /// Watch `dirs`.
        #[must_use]
        pub fn new(dirs: Vec<PathBuf>) -> Self {
            Self {
                // Warm-start: don't re-report files that predate the
                // agent; only writes after start-up are sensitive here.
                watcher: SensitiveDirWatcher::new(DlpChannel::FileWrite, dirs).warm_started(),
            }
        }
    }

    #[async_trait]
    impl ChannelInterceptor for WindowsFileWriteMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::FileWrite
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            self.watcher.next_event().await
        }
    }

    /// Windows clipboard monitor — reads via PowerShell
    /// `Get-Clipboard`.
    ///
    /// Read on demand each [`next_event`]; [`shutdown`](Self::shutdown)
    /// makes a subsequent call return `Ok(None)` per the
    /// [`ChannelInterceptor`] contract.
    #[derive(Clone, Debug, Default)]
    pub struct WindowsClipboardMonitor {
        closed: Arc<AtomicBool>,
    }

    impl WindowsClipboardMonitor {
        /// A new, open clipboard monitor.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Tear the monitor down; the next [`next_event`] returns
        /// `Ok(None)`.
        pub fn shutdown(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl ChannelInterceptor for WindowsClipboardMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::Clipboard
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let output = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Get-Clipboard -Raw"])
                .output()
                .map_err(|e| {
                    ChannelError::Unavailable(format!("Get-Clipboard unavailable: {e}"))
                })?;
            if !output.status.success() {
                return Err(ChannelError::Init(format!(
                    "Get-Clipboard exited with status {}",
                    output.status
                )));
            }
            let metadata = ContentMetadata {
                filename: None,
                content_type: Some("text/plain".to_owned()),
                source: Some("clipboard".to_owned()),
                mip_labels: Vec::new(),
            };
            Ok(Some(ContentEvent {
                channel: DlpChannel::Clipboard,
                content: output.stdout,
                metadata,
            }))
        }
    }
}

/// Lock a mutex, recovering from poisoning (a panic in a previous
/// holder must not wedge the DLP source).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn mime_lookup_covers_common_office_types() {
        assert_eq!(mime_for_path(Path::new("a.csv")), Some("text/csv"));
        assert_eq!(mime_for_path(Path::new("a.PDF")), Some("application/pdf"));
        assert_eq!(mime_for_path(Path::new("a.unknownext")), None);
        assert_eq!(mime_for_path(Path::new("noext")), None);
    }

    #[test]
    fn parse_proc_mounts_decodes_escapes() {
        let contents = "\
/dev/sda1 / ext4 rw 0 0
/dev/sdb1 /media/My\\040Drive vfat rw 0 0
tmpfs /run tmpfs rw 0 0
";
        let mounts = parse_proc_mounts(contents);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[0].device, "/dev/sda1");
        assert_eq!(mounts[0].mount_point, PathBuf::from("/"));
        assert_eq!(mounts[1].mount_point, PathBuf::from("/media/My Drive"));
        assert_eq!(mounts[1].fstype, "vfat");
        assert_eq!(mounts[2].device, "tmpfs");
    }

    #[test]
    fn parse_proc_mounts_decodes_multibyte_utf8_labels() {
        // The kernel octal-escapes each byte of a non-ASCII path, so a
        // UTF-8 label is a run of escapes: "Café" → "Caf\303\251",
        // "Привет" (Cyrillic) is all two-byte sequences. Decoding each
        // escape independently to a char would yield Latin-1 mojibake
        // ("CafÃ©") that no longer matches the real mount point.
        let contents = "/dev/sdb1 /media/Caf\\303\\251 vfat rw 0 0\n/dev/sdc1 /media/\\320\\237\\321\\200\\320\\270\\320\\262\\320\\265\\321\\202 vfat rw 0 0\n";
        let mounts = parse_proc_mounts(contents);
        assert_eq!(mounts.len(), 2);
        assert_eq!(mounts[0].mount_point, PathBuf::from("/media/Café"));
        assert_eq!(mounts[1].mount_point, PathBuf::from("/media/Привет"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dir_watcher_reports_new_file_then_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("secret.txt"), b"hello ssn 123-45-6789").expect("write");

        let watcher =
            SensitiveDirWatcher::new(DlpChannel::FileWrite, vec![dir.path().to_path_buf()])
                .with_poll_interval(Duration::from_millis(10));

        // First scan reports the file.
        assert_eq!(watcher.scan(), 1);
        let event = watcher.try_pop().expect("event");
        assert_eq!(event.channel, DlpChannel::FileWrite);
        assert_eq!(event.content, b"hello ssn 123-45-6789");
        assert_eq!(event.metadata.filename.as_deref(), Some("secret.txt"));
        assert_eq!(event.metadata.content_type.as_deref(), Some("text/plain"));

        // Re-scan with no change reports nothing.
        assert_eq!(watcher.scan(), 0);
        assert!(watcher.try_pop().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn warm_started_watcher_skips_preexisting_then_reports_new_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("old.txt"), b"predates the agent").expect("write");

        let watcher =
            SensitiveDirWatcher::new(DlpChannel::FileWrite, vec![dir.path().to_path_buf()])
                .warm_started();

        // First scan primes the watermark for pre-existing files and
        // queues nothing — no spurious burst on start-up.
        assert_eq!(watcher.scan(), 0);
        assert!(watcher.try_pop().is_none());

        // A genuinely new write after start-up is reported.
        std::fs::write(dir.path().join("new.txt"), b"written after start").expect("write");
        assert_eq!(watcher.scan(), 1);
        let event = watcher.try_pop().expect("event");
        assert_eq!(event.metadata.filename.as_deref(), Some("new.txt"));
        assert!(watcher.try_pop().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dir_watcher_prunes_watermarks_for_deleted_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write a");
        std::fs::write(dir.path().join("b.txt"), b"bravo").expect("write b");

        let watcher =
            SensitiveDirWatcher::new(DlpChannel::FileWrite, vec![dir.path().to_path_buf()]);

        // First scan reports both files and records a watermark each.
        assert_eq!(watcher.scan(), 2);
        assert_eq!(watcher.watermark_count(), 2);
        while watcher.try_pop().is_some() {}

        // Delete one file. The next complete scan reports nothing new
        // and prunes the stale watermark so the map cannot grow without
        // bound on a long-lived agent over a high-churn directory.
        std::fs::remove_file(dir.path().join("a.txt")).expect("rm a");
        assert_eq!(watcher.scan(), 0);
        assert_eq!(watcher.watermark_count(), 1);
        assert!(watcher.try_pop().is_none());

        // The surviving file stays tracked (a fresh write of c.txt is
        // reported, b.txt is not re-reported), and pruning has not
        // resurrected the deleted entry — the map tracks exactly the two
        // live files.
        std::fs::write(dir.path().join("c.txt"), b"charlie").expect("write c");
        assert_eq!(watcher.scan(), 1);
        assert_eq!(watcher.watermark_count(), 2);
        let event = watcher.try_pop().expect("event");
        assert_eq!(event.metadata.filename.as_deref(), Some("c.txt"));
        assert!(watcher.try_pop().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dir_watcher_respects_byte_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("big.bin"), vec![b'x'; 10_000]).expect("write");
        let watcher =
            SensitiveDirWatcher::new(DlpChannel::FileWrite, vec![dir.path().to_path_buf()])
                .with_max_file_bytes(128);
        assert_eq!(watcher.scan(), 1);
        let event = watcher.try_pop().expect("event");
        assert_eq!(event.content.len(), 128);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dir_watcher_next_event_yields_then_closes() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"alpha").expect("write");
        let watcher =
            SensitiveDirWatcher::new(DlpChannel::FileWrite, vec![dir.path().to_path_buf()]);

        let first = watcher.next_event().await.expect("ok").expect("some");
        assert_eq!(first.content, b"alpha");

        // No more new files; shut down and confirm clean close.
        watcher.shutdown();
        assert!(watcher.next_event().await.expect("ok").is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn browser_upload_bridge_surfaces_submitted_body() {
        let bridge = BrowserUploadBridge::new();
        bridge.submit(
            b"upload body".to_vec(),
            Some("report.csv".to_owned()),
            Some("text/csv".to_owned()),
        );
        let event = bridge.next_event().await.expect("ok").expect("some");
        assert_eq!(event.channel, DlpChannel::BrowserUpload);
        assert_eq!(event.content, b"upload body");
        assert_eq!(event.metadata.filename.as_deref(), Some("report.csv"));

        bridge.shutdown();
        assert!(bridge.next_event().await.expect("ok").is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_removable_detection_and_usb_scan() {
        // Fake sysfs: /sys/block/sdb/removable == "1", sda == "0".
        let sys = tempfile::tempdir().expect("sys");
        std::fs::create_dir_all(sys.path().join("sdb")).expect("mk sdb");
        std::fs::write(sys.path().join("sdb/removable"), "1\n").expect("sdb flag");
        std::fs::create_dir_all(sys.path().join("sda")).expect("mk sda");
        std::fs::write(sys.path().join("sda/removable"), "0\n").expect("sda flag");

        // Fake removable mount with a file on it.
        let mount_dir = tempfile::tempdir().expect("mount");
        std::fs::write(mount_dir.path().join("copied.txt"), b"exfiltrated").expect("file");

        let mounts = format!(
            "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 {} vfat rw 0 0\n",
            mount_dir.path().display()
        );
        let proc = tempfile::NamedTempFile::new().expect("proc");
        std::fs::write(proc.path(), mounts).expect("write mounts");

        let detector = LinuxRemovableStorageMonitor::with_roots(
            proc.path().to_path_buf(),
            sys.path().to_path_buf(),
        );
        let removable = detector.removable_mounts();
        assert_eq!(removable.len(), 1);
        assert_eq!(removable[0].device, "/dev/sdb1");

        let monitor = LinuxUsbTransferMonitor::new(detector);
        let event = monitor.next_event().await.expect("ok").expect("some");
        assert_eq!(event.channel, DlpChannel::UsbTransfer);
        assert_eq!(event.content, b"exfiltrated");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn clipboard_monitor_honors_shutdown_with_none() {
        // After shutdown the stateless clipboard reader must observe the
        // ChannelInterceptor contract and return Ok(None) — a consumer
        // looping to end-of-stream then terminates cleanly instead of
        // hanging on the interceptor for a signal it would never get.
        let monitor = LinuxClipboardMonitor::new();
        monitor.shutdown();
        let result = monitor
            .next_event()
            .await
            .expect("shutdown is not an error");
        assert!(
            result.is_none(),
            "post-shutdown next_event must yield None, got {result:?}"
        );
    }
}
