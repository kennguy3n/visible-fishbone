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
            ..ContentMetadata::default()
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
            ..ContentMetadata::default()
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

// ---------------------------------------------------------------------------
// Per-OS ChannelInterceptor backends
// ---------------------------------------------------------------------------
//
// Each desktop OS exposes its own kernel facility for the five DLP
// channels; the backends live in a per-OS file module behind a
// `cfg(target_os)` gate and are re-exported here so callers refer to
// them as `sng_pal::dlp::<Backend>` regardless of platform. The
// portable `SensitiveDirWatcher` above remains the fail-safe fallback
// each file-write / print backend falls back to when its native hook
// cannot be initialised (e.g. an inotify-instance ceiling is hit, or
// the host denies the netlink bind).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    LinuxClipboardMonitor, LinuxFileWriteMonitor, LinuxPrintMonitor, LinuxRemovableStorageMonitor,
    LinuxUsbTransferMonitor, UdevEvent, UdevMonitor, parse_uevent,
};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{MacClipboardMonitor, MacFileWriteMonitor, MacPrintMonitor, MacUsbTransferMonitor};

#[cfg(target_os = "windows")]
mod windows_impl;
#[cfg(target_os = "windows")]
pub use windows_impl::{
    WindowsClipboardMonitor, WindowsFileWriteMonitor, WindowsPrintMonitor,
    WindowsUsbTransferMonitor, WindowsWfpEgressGuard,
};

/// Lock a mutex, recovering from poisoning (a panic in a previous
/// holder must not wedge the DLP source).
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Build the metadata stamped on a clipboard content event. Shared by
/// every per-OS clipboard backend so the engine sees an identical
/// `source`/`content_type` regardless of platform.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
pub(crate) fn clipboard_metadata() -> ContentMetadata {
    ContentMetadata {
        filename: None,
        content_type: Some("text/plain".to_owned()),
        source: Some("clipboard".to_owned()),
        mip_labels: Vec::new(),
        ..ContentMetadata::default()
    }
}

/// FNV-1a hash for clipboard-selection dedup. Not cryptographic; only
/// used to detect "the selection changed since we last read it" so a
/// backend does not re-emit an unchanged clipboard.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
pub(crate) fn content_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
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

    // A symlink that points back at an ancestor directory cannot send the
    // walker into a loop: `DirEntry::metadata` is lstat on Unix, so the
    // symlink reports neither `is_dir` nor `is_file` and `walk` skips it
    // without descending. The only real file is reported exactly once and
    // the scan terminates regardless of the cycle.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn dir_watcher_does_not_follow_symlink_loops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("real.txt"), b"ssn 123-45-6789").expect("write");
        // root/loop -> root  (a self-referential cycle)
        std::os::unix::fs::symlink(root, root.join("loop")).expect("symlink");

        let watcher = SensitiveDirWatcher::new(DlpChannel::FileWrite, vec![root.to_path_buf()])
            .with_poll_interval(Duration::from_millis(10));

        // Exactly one event (real.txt); the symlinked dir is not traversed.
        assert_eq!(watcher.scan(), 1);
        let event = watcher.try_pop().expect("event");
        assert_eq!(event.metadata.filename.as_deref(), Some("real.txt"));
        assert!(watcher.try_pop().is_none());
        // Only the single real file holds a watermark — the symlink left
        // no entry behind.
        assert_eq!(watcher.watermark_count(), 1);
        // A re-scan over the same cycle still terminates and reports nothing.
        assert_eq!(watcher.scan(), 0);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_uevent_decodes_block_partition_add() {
        // A kernel block `add` uevent: summary line then NUL-separated
        // KEY=VALUE records, exactly as delivered on the netlink socket.
        let payload = b"add@/devices/pci/usb/sdb1\0ACTION=add\0SUBSYSTEM=block\0DEVNAME=sdb1\0DEVTYPE=partition\0";
        let event = parse_uevent(payload).expect("parses");
        assert_eq!(event.action, "add");
        assert_eq!(event.subsystem.as_deref(), Some("block"));
        assert_eq!(event.devname.as_deref(), Some("sdb1"));
        assert!(event.is_block_partition_add());

        // A whole-disk add (DEVTYPE=disk) is not a mountable partition.
        let disk = b"add@/x\0ACTION=add\0SUBSYSTEM=block\0DEVTYPE=disk\0";
        assert!(!parse_uevent(disk).expect("parses").is_block_partition_add());

        // No ACTION → not a usable uevent.
        assert!(parse_uevent(b"SUBSYSTEM=block\0").is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn inotify_file_write_monitor_reports_close_write() {
        // The native inotify backend must report a file the instant its
        // writer closes the descriptor — edge-triggered, no poll cadence.
        let dir = tempfile::tempdir().expect("dir");
        let monitor = LinuxFileWriteMonitor::new(vec![dir.path().to_path_buf()]);

        // Write a sensitive file after the watch is armed.
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"4111111111111111").expect("write");

        let event = tokio::time::timeout(Duration::from_secs(5), monitor.next_event())
            .await
            .expect("inotify should report the write within 5s")
            .expect("ok")
            .expect("some");
        assert_eq!(event.channel, DlpChannel::FileWrite);
        assert_eq!(event.content, b"4111111111111111");
        assert_eq!(event.metadata.filename.as_deref(), Some("secret.txt"));
        monitor.shutdown();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn inotify_watches_subdirectories_created_after_start() {
        // A directory created under a watched root after start-up must be
        // armed dynamically so writes inside it are still observed.
        let dir = tempfile::tempdir().expect("dir");
        let monitor = LinuxFileWriteMonitor::new(vec![dir.path().to_path_buf()]);

        let sub = dir.path().join("nested");
        std::fs::create_dir(&sub).expect("mkdir");
        // Give the worker a moment to arm the new sub-directory watch.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(sub.join("deep.txt"), b"ssn 123-45-6789").expect("write");

        let event = tokio::time::timeout(Duration::from_secs(5), monitor.next_event())
            .await
            .expect("inotify should report the nested write within 5s")
            .expect("ok")
            .expect("some");
        assert_eq!(event.metadata.filename.as_deref(), Some("deep.txt"));
        monitor.shutdown();
    }

    // Live X11 clipboard round-trip. Ignored by default: it needs a
    // reachable X server (`DISPLAY`) and so cannot run on headless CI;
    // run locally with `cargo test -p sng-pal -- --ignored x11_clipboard`.
    // It spins up a real CLIPBOARD selection owner with x11rb, sets the
    // selection, and asserts the native monitor reports the bytes via
    // the XFIXES edge-trigger + ConvertSelection path.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires a live X server (DISPLAY)"]
    async fn x11_clipboard_roundtrip_reports_selection() {
        use x11rb::connection::Connection;
        use x11rb::protocol::Event;
        use x11rb::protocol::xproto::{
            ConnectionExt, CreateWindowAux, EventMask, PropMode, SELECTION_NOTIFY_EVENT,
            SelectionNotifyEvent, WindowClass,
        };
        use x11rb::wrapper::ConnectionExt as _;

        const SECRET: &[u8] = b"live-clip-4111111111111111";

        // Arm the monitor first so it observes the SET_SELECTION_OWNER
        // edge the owner thread produces below.
        let monitor = LinuxClipboardMonitor::new();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Selection-owner thread: owns CLIPBOARD and serves UTF8_STRING.
        let owner = std::thread::spawn(|| {
            let Ok((conn, screen_num)) = x11rb::connect(None) else {
                return;
            };
            let root = conn.setup().roots[screen_num].root;
            let win = conn.generate_id().unwrap();
            conn.create_window(
                0,
                win,
                root,
                0,
                0,
                1,
                1,
                0,
                WindowClass::INPUT_OUTPUT,
                0,
                &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            )
            .unwrap();
            let clipboard = conn
                .intern_atom(false, b"CLIPBOARD")
                .unwrap()
                .reply()
                .unwrap()
                .atom;
            let utf8 = conn
                .intern_atom(false, b"UTF8_STRING")
                .unwrap()
                .reply()
                .unwrap()
                .atom;
            conn.set_selection_owner(win, clipboard, x11rb::CURRENT_TIME)
                .unwrap();
            conn.flush().unwrap();
            // Serve conversion requests until the monitor has read once.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while std::time::Instant::now() < deadline {
                match conn.poll_for_event() {
                    Ok(Some(Event::SelectionRequest(req))) if req.target == utf8 => {
                        conn.change_property8(
                            PropMode::REPLACE,
                            req.requestor,
                            req.property,
                            utf8,
                            SECRET,
                        )
                        .unwrap();
                        let notify = SelectionNotifyEvent {
                            response_type: SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: req.time,
                            requestor: req.requestor,
                            selection: req.selection,
                            target: req.target,
                            property: req.property,
                        };
                        conn.send_event(false, req.requestor, EventMask::NO_EVENT, notify)
                            .unwrap();
                        conn.flush().unwrap();
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
                    Err(_) => break,
                }
            }
        });

        let event = tokio::time::timeout(Duration::from_secs(6), monitor.next_event())
            .await
            .expect("monitor should report the selection within 6s")
            .expect("ok")
            .expect("some");
        assert_eq!(event.channel, DlpChannel::Clipboard);
        assert_eq!(event.content, SECRET);
        monitor.shutdown();
        let _ = owner.join();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn inotify_monitor_honors_shutdown_with_none() {
        let dir = tempfile::tempdir().expect("dir");
        let monitor = LinuxFileWriteMonitor::new(vec![dir.path().to_path_buf()]);
        monitor.shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), monitor.next_event())
            .await
            .expect("shutdown should unblock next_event")
            .expect("shutdown is not an error");
        assert!(result.is_none(), "post-shutdown must yield None");
    }
}
