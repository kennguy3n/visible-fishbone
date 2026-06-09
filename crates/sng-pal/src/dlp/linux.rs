// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Linux DLP backends.
//!
//! These are the native, edge-triggered Linux sources for the five
//! DLP channels. They are the production upgrade over the portable
//! [`SensitiveDirWatcher`](super::SensitiveDirWatcher) poll watcher:
//!
//! * **File write** — [`LinuxFileWriteMonitor`] watches the configured
//!   sensitive directories with `inotify` (`IN_CLOSE_WRITE` /
//!   `IN_MOVED_TO`): the kernel delivers a write the instant the
//!   writer closes the descriptor, so a quiet endpoint costs no CPU
//!   (the watcher thread blocks in `poll`) instead of waking every
//!   poll interval. New sub-directories created under a watched root
//!   are watched dynamically (`IN_CREATE`). If `inotify` cannot be
//!   initialised (the per-process instance/watch ceiling is hit, or
//!   the syscall is sandboxed away) the monitor falls back to the
//!   portable poll watcher so file-write coverage is never lost.
//! * **Print** — [`LinuxPrintMonitor`] watches the CUPS spool
//!   directory (`/var/spool/cups`) the same way: a queued job's data
//!   file is reported the moment cupsd finishes spooling it.
//! * **USB transfer** — [`UdevMonitor`] opens the
//!   `NETLINK_KOBJECT_UEVENT` netlink socket — the exact kernel uevent
//!   multicast `udev` itself consumes — and decodes block-device
//!   `add` / `remove` uevents. [`LinuxUsbTransferMonitor`] uses it to
//!   learn of a newly-attached removable volume edge-triggered,
//!   confirms it is removable via `/sys/block/<dev>/removable`, waits
//!   for it to mount, and reports the files written onto it.
//! * **Clipboard** — [`LinuxClipboardMonitor`] reads the desktop
//!   selection. On X11 it speaks the X protocol directly through
//!   [`x11rb`] and arms the XFIXES `SET_SELECTION_OWNER` notification
//!   so a `CLIPBOARD` ownership change wakes it edge-triggered, then
//!   fetches the new selection with `ConvertSelection`. On Wayland —
//!   whose security model denies an unfocused client direct clipboard
//!   reads — it delegates to the compositor's own `wl-paste` data
//!   bridge; on a headless host with neither, it reports
//!   [`ChannelError::Unavailable`].

use super::{DEFAULT_MAX_FILE_BYTES, MountEntry, RemovableMount, SensitiveDirWatcher, mime_for_path};
use async_trait::async_trait;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::Read;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use super::lock;

/// Maximum directory depth the inotify watcher arms watches to. Bounds
/// the watch-descriptor count (an inotify instance is capped by
/// `/proc/sys/fs/inotify/max_user_watches`) on a deep tree.
const MAX_INOTIFY_DEPTH: usize = 8;

/// Bound on the watch descriptors a single monitor arms. A pathological
/// directory tree cannot exhaust the per-user inotify watch budget and
/// starve the rest of the agent's watchers.
const MAX_INOTIFY_WATCHES: usize = 8192;

/// Cadence at which the inotify / netlink worker threads re-check the
/// shutdown flag while no kernel event is pending. The thread is
/// otherwise asleep in `poll`, so this only bounds teardown latency on
/// an idle channel — it is not a poll loop over the watched data.
const SHUTDOWN_POLL: Duration = Duration::from_millis(500);

/// Convert a (small) [`Duration`] to a nix [`PollTimeout`]. Our
/// timeouts are sub-second, well inside the representable range; an
/// out-of-range value falls back to the shutdown tick.
fn poll_timeout(d: Duration) -> PollTimeout {
    PollTimeout::try_from(d).unwrap_or_else(|_| {
        PollTimeout::try_from(SHUTDOWN_POLL).unwrap_or(PollTimeout::NONE)
    })
}

/// Default directories an endpoint watches for sensitive-file writes
/// when the policy does not override them.
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

// ---------------------------------------------------------------------------
// inotify edge-triggered directory watcher
// ---------------------------------------------------------------------------

/// Shared state between an [`InotifyWatcher`]'s worker thread and its
/// `next_event` consumer.
#[derive(Debug, Default)]
struct InotifyShared {
    buffer: Mutex<VecDeque<ContentEvent>>,
    closed: AtomicBool,
    /// Set once the worker thread has exited (clean close or fatal
    /// inotify error), so `next_event` returns `Ok(None)` after the
    /// buffer drains rather than awaiting an event that will never come.
    drained: AtomicBool,
}

/// Edge-triggered directory watcher built on `inotify`.
///
/// One background OS thread owns the inotify instance and blocks in
/// `poll` until the kernel signals a watched event or the shutdown
/// deadline elapses; it reads `IN_CLOSE_WRITE` / `IN_MOVED_TO` files
/// into bounded [`ContentEvent`]s and arms watches on `IN_CREATE`d
/// sub-directories. The async [`ChannelInterceptor::next_event`] just
/// drains the shared buffer.
#[derive(Debug)]
struct InotifyWatcher {
    channel: DlpChannel,
    shared: Arc<InotifyShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl InotifyWatcher {
    /// Arm an inotify watch over `dirs` (recursively, depth- and
    /// count-bounded). Returns `Err` if the inotify instance cannot be
    /// created or no directory could be watched, so the caller can fall
    /// back to the portable poll watcher.
    fn start(channel: DlpChannel, dirs: &[PathBuf], max_file_bytes: usize) -> Result<Self, String> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .map_err(|e| format!("inotify_init: {e}"))?;

        let mut wd_paths: HashMap<WatchDescriptor, PathBuf> = HashMap::new();
        let mut armed = 0usize;
        for dir in dirs {
            arm_recursive(&inotify, dir, 0, &mut wd_paths, &mut armed);
        }
        if armed == 0 {
            return Err("no watchable directory".to_owned());
        }

        let shared = Arc::new(InotifyShared::default());
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name(format!("sng-dlp-inotify-{}", channel.as_str()))
            .spawn(move || inotify_worker(inotify, wd_paths, channel, max_file_bytes, &worker_shared))
            .map_err(|e| format!("spawn inotify worker: {e}"))?;

        Ok(Self {
            channel,
            shared,
            worker: Mutex::new(Some(worker)),
        })
    }

    fn shutdown(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        if let Some(handle) = lock(&self.worker).take() {
            // The worker observes `closed` within one `SHUTDOWN_POLL`
            // tick and exits; joining keeps the inotify fd from
            // outliving the monitor.
            let _ = handle.join();
        }
    }
}

impl Drop for InotifyWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for InotifyWatcher {
    fn channel(&self) -> DlpChannel {
        self.channel
    }

    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        loop {
            if let Some(event) = lock(&self.shared.buffer).pop_front() {
                return Ok(Some(event));
            }
            if self.shared.closed.load(Ordering::SeqCst) || self.shared.drained.load(Ordering::SeqCst)
            {
                // Drain any final events the worker queued before exit,
                // then report the clean close.
                if let Some(event) = lock(&self.shared.buffer).pop_front() {
                    return Ok(Some(event));
                }
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Arm an inotify watch on `dir` and (depth-bounded) its
/// sub-directories, recording each watch-descriptor → path mapping.
fn arm_recursive(
    inotify: &Inotify,
    dir: &Path,
    depth: usize,
    wd_paths: &mut HashMap<WatchDescriptor, PathBuf>,
    armed: &mut usize,
) {
    if depth > MAX_INOTIFY_DEPTH || *armed >= MAX_INOTIFY_WATCHES {
        return;
    }
    let flags = AddWatchFlags::IN_CLOSE_WRITE
        | AddWatchFlags::IN_MOVED_TO
        | AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_ONLYDIR;
    let Ok(wd) = inotify.add_watch(dir, flags) else {
        return;
    };
    wd_paths.insert(wd, dir.to_path_buf());
    *armed += 1;

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *armed >= MAX_INOTIFY_WATCHES {
            break;
        }
        let path = entry.path();
        // `symlink_metadata` (lstat) so a symlinked directory is not
        // descended into — the same loop-safety the poll walker relies
        // on, and it keeps the watch set bounded to the real tree.
        if let Ok(meta) = std::fs::symlink_metadata(&path)
            && meta.is_dir()
        {
            arm_recursive(inotify, &path, depth + 1, wd_paths, armed);
        }
    }
}

/// The blocking inotify worker. Owns the inotify instance for its
/// lifetime and pushes content events into the shared buffer.
//
// `inotify` and `wd_paths` are taken by value so the worker owns them
// for the thread's whole lifetime (the fd must outlive every watch);
// they are mutated, not merely borrowed.
#[allow(clippy::needless_pass_by_value)]
fn inotify_worker(
    inotify: Inotify,
    mut wd_paths: HashMap<WatchDescriptor, PathBuf>,
    channel: DlpChannel,
    max_file_bytes: usize,
    shared: &InotifyShared,
) {
    let mut armed = wd_paths.len();
    loop {
        if shared.closed.load(Ordering::SeqCst) {
            break;
        }
        // Block until the inotify fd is readable or the shutdown tick
        // elapses. An idle channel parks here at ~0% CPU.
        let borrowed = inotify.as_fd();
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match nix::poll::poll(&mut fds, poll_timeout(SHUTDOWN_POLL)) {
            // timeout (re-check shutdown) or interrupted syscall: loop.
            Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
            Ok(_) => {} // readable
            Err(_) => break, // fd is wedged; stop the worker
        }
        let events = match inotify.read_events() {
            Ok(events) => events,
            Err(nix::errno::Errno::EAGAIN) => continue,
            Err(_) => break,
        };
        for event in events {
            let Some(parent) = wd_paths.get(&event.wd) else {
                continue;
            };
            let Some(name) = event.name.as_ref() else {
                continue;
            };
            let path = parent.join(name);
            let is_dir = event.mask.contains(AddWatchFlags::IN_ISDIR);
            if is_dir {
                // A new sub-directory: arm it so writes inside are seen
                // too. Bounded by the watch ceiling.
                if event.mask.contains(AddWatchFlags::IN_CREATE) && armed < MAX_INOTIFY_WATCHES {
                    let flags = AddWatchFlags::IN_CLOSE_WRITE
                        | AddWatchFlags::IN_MOVED_TO
                        | AddWatchFlags::IN_CREATE
                        | AddWatchFlags::IN_ONLYDIR;
                    if let Ok(wd) = inotify.add_watch(&path, flags) {
                        wd_paths.insert(wd, path);
                        armed += 1;
                    }
                }
                continue;
            }
            // A regular-file close-after-write or move-into: read it.
            if let Some(event) = read_file_event(&path, channel, max_file_bytes) {
                lock(&shared.buffer).push_back(event);
            }
        }
    }
    shared.drained.store(true, Ordering::SeqCst);
}

/// Read up to `max_file_bytes` of `path` into a content event, or
/// `None` if the file vanished / is unreadable / is not a regular file.
fn read_file_event(path: &Path, channel: DlpChannel, max_file_bytes: usize) -> Option<ContentEvent> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let cap = u64::try_from(max_file_bytes).unwrap_or(u64::MAX);
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
        channel,
        content: buf,
        metadata,
    })
}

// ---------------------------------------------------------------------------
// File-write channel
// ---------------------------------------------------------------------------

/// Linux file-write monitor.
///
/// Prefers the edge-triggered [`InotifyWatcher`]; if inotify cannot be
/// initialised it transparently falls back to the portable
/// [`SensitiveDirWatcher`] poll watcher so coverage is never lost.
#[derive(Debug)]
pub struct LinuxFileWriteMonitor {
    inner: FileWriteInner,
}

#[derive(Debug)]
enum FileWriteInner {
    Inotify(InotifyWatcher),
    Poll(SensitiveDirWatcher),
}

impl LinuxFileWriteMonitor {
    /// Watch `dirs` (empty → the default sensitive set).
    #[must_use]
    pub fn new(dirs: Vec<PathBuf>) -> Self {
        Self::with_max_file_bytes(dirs, DEFAULT_MAX_FILE_BYTES)
    }

    /// Watch `dirs` with an explicit per-file read ceiling.
    #[must_use]
    pub fn with_max_file_bytes(dirs: Vec<PathBuf>, max_file_bytes: usize) -> Self {
        let dirs = if dirs.is_empty() {
            default_sensitive_dirs()
        } else {
            dirs
        };
        match InotifyWatcher::start(DlpChannel::FileWrite, &dirs, max_file_bytes) {
            Ok(watcher) => Self {
                inner: FileWriteInner::Inotify(watcher),
            },
            Err(reason) => {
                tracing::info!(
                    target: "sng_pal::dlp",
                    %reason,
                    "inotify unavailable for file-write channel; falling back to poll watcher"
                );
                // Warm-start: files that predate the agent are recorded
                // as the watermark, not re-reported as fresh writes.
                let watcher = SensitiveDirWatcher::new(DlpChannel::FileWrite, dirs)
                    .with_max_file_bytes(max_file_bytes)
                    .warm_started();
                Self {
                    inner: FileWriteInner::Poll(watcher),
                }
            }
        }
    }

    /// Tear the monitor down.
    pub fn shutdown(&self) {
        match &self.inner {
            FileWriteInner::Inotify(w) => w.shutdown(),
            FileWriteInner::Poll(w) => w.shutdown(),
        }
    }
}

#[async_trait]
impl ChannelInterceptor for LinuxFileWriteMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::FileWrite
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        match &self.inner {
            FileWriteInner::Inotify(w) => w.next_event().await,
            FileWriteInner::Poll(w) => w.next_event().await,
        }
    }
}

// ---------------------------------------------------------------------------
// Print channel
// ---------------------------------------------------------------------------

/// Linux print monitor — watches the CUPS spool directory for queued
/// job data, edge-triggered via inotify (poll fallback).
#[derive(Debug)]
pub struct LinuxPrintMonitor {
    inner: FileWriteInner,
}

impl LinuxPrintMonitor {
    /// Watch `spool_dir` (default `/var/spool/cups`).
    #[must_use]
    pub fn new(spool_dir: Option<PathBuf>) -> Self {
        let dir = spool_dir.unwrap_or_else(|| PathBuf::from("/var/spool/cups"));
        let dirs = vec![dir];
        match InotifyWatcher::start(DlpChannel::Print, &dirs, DEFAULT_MAX_FILE_BYTES) {
            Ok(watcher) => Self {
                inner: FileWriteInner::Inotify(watcher),
            },
            Err(reason) => {
                tracing::info!(
                    target: "sng_pal::dlp",
                    %reason,
                    "inotify unavailable for print channel; falling back to poll watcher"
                );
                Self {
                    inner: FileWriteInner::Poll(SensitiveDirWatcher::new(DlpChannel::Print, dirs)),
                }
            }
        }
    }

    /// Tear the monitor down.
    pub fn shutdown(&self) {
        match &self.inner {
            FileWriteInner::Inotify(w) => w.shutdown(),
            FileWriteInner::Poll(w) => w.shutdown(),
        }
    }
}

#[async_trait]
impl ChannelInterceptor for LinuxPrintMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Print
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        match &self.inner {
            FileWriteInner::Inotify(w) => w.next_event().await,
            FileWriteInner::Poll(w) => w.next_event().await,
        }
    }
}

// ---------------------------------------------------------------------------
// Removable-storage detection (procfs / sysfs)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// udev / netlink uevent monitor
// ---------------------------------------------------------------------------

/// A decoded kernel uevent relevant to removable-storage monitoring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdevEvent {
    /// The action: `add`, `remove`, `change`, …
    pub action: String,
    /// The `DEVNAME` (e.g. `sdb1`) if the uevent carried one.
    pub devname: Option<String>,
    /// The `SUBSYSTEM` (e.g. `block`).
    pub subsystem: Option<String>,
    /// The `DEVTYPE` (e.g. `partition`, `disk`).
    pub devtype: Option<String>,
}

impl UdevEvent {
    /// Whether this is a block-device partition `add` — the signal that
    /// a removable volume has just appeared and may be about to mount.
    #[must_use]
    pub fn is_block_partition_add(&self) -> bool {
        self.action == "add"
            && self.subsystem.as_deref() == Some("block")
            && self.devtype.as_deref() == Some("partition")
    }
}

/// Parse a kernel uevent payload — a run of `KEY=VALUE` records
/// separated by NUL bytes, the first record being the event summary
/// line (`add@/devices/...`). Returns `None` if the payload carries no
/// `ACTION`.
#[must_use]
pub fn parse_uevent(payload: &[u8]) -> Option<UdevEvent> {
    let mut action = None;
    let mut devname = None;
    let mut subsystem = None;
    let mut devtype = None;
    for record in payload.split(|&b| b == 0) {
        if record.is_empty() {
            continue;
        }
        let Ok(text) = std::str::from_utf8(record) else {
            continue;
        };
        let Some((key, value)) = text.split_once('=') else {
            continue;
        };
        match key {
            "ACTION" => action = Some(value.to_owned()),
            "DEVNAME" => devname = Some(value.to_owned()),
            "SUBSYSTEM" => subsystem = Some(value.to_owned()),
            "DEVTYPE" => devtype = Some(value.to_owned()),
            _ => {}
        }
    }
    Some(UdevEvent {
        action: action?,
        devname,
        subsystem,
        devtype,
    })
}

/// Edge-triggered removable-device monitor over the kernel uevent
/// netlink multicast (`NETLINK_KOBJECT_UEVENT`).
///
/// This is the same socket `udev` listens on; binding to multicast
/// group 1 receives every kernel uevent. Block-device partition `add`
/// events are the trigger the USB-transfer channel waits on. The
/// socket bind can require privilege on some hosts; [`Self::open`]
/// surfaces that as an error so the caller degrades gracefully.
#[derive(Debug)]
pub struct UdevMonitor {
    fd: std::os::fd::OwnedFd,
}

impl UdevMonitor {
    /// Open and bind the netlink uevent socket.
    pub fn open() -> Result<Self, ChannelError> {
        use nix::sys::socket::{
            AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, socket,
        };
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            SockProtocol::NetlinkKObjectUEvent,
        )
        .map_err(|e| ChannelError::Init(format!("netlink uevent socket: {e}")))?;
        // pid 0 = let the kernel assign; group 1 = kernel uevent
        // multicast (group 2 is the udevd-rebroadcast group).
        let addr = NetlinkAddr::new(0, 1);
        bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &addr)
            .map_err(|e| ChannelError::Unavailable(format!("bind netlink uevent group: {e}")))?;
        Ok(Self { fd })
    }

    /// Block until the next uevent arrives (or `timeout` elapses,
    /// yielding `Ok(None)`), decoding it. Spurious / unparsable
    /// payloads yield `Ok(None)` so the caller loops.
    fn next(&self, timeout: Duration) -> Result<Option<UdevEvent>, ChannelError> {
        let borrowed = self.fd.as_fd();
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match nix::poll::poll(&mut fds, poll_timeout(timeout)) {
            // Timeout or interrupted syscall: no event this round.
            Ok(0) | Err(nix::errno::Errno::EINTR) => return Ok(None),
            Ok(_) => {}
            Err(e) => return Err(ChannelError::Init(format!("poll netlink: {e}"))),
        }
        let mut buf = [0u8; 8192];
        match nix::sys::socket::recv(
            std::os::fd::AsRawFd::as_raw_fd(&self.fd),
            &mut buf,
            nix::sys::socket::MsgFlags::empty(),
        ) {
            // Empty datagram or would-block: nothing to decode.
            Ok(0) | Err(nix::errno::Errno::EAGAIN) => Ok(None),
            Ok(n) => Ok(parse_uevent(&buf[..n])),
            Err(e) => Err(ChannelError::Init(format!("recv netlink: {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// USB-transfer channel
// ---------------------------------------------------------------------------

/// Fallback wake cadence when no removable volume is mounted and no
/// udev netlink socket is available to push device-arrival events. A
/// long interval keeps an endpoint with no USB device attached — the
/// overwhelming common case — at effectively zero cost.
const USB_IDLE_FALLBACK: Duration = Duration::from_secs(5);

/// Wake ceiling when parked waiting for a udev arrival notification.
/// The wait is normally ended by the notify; this only bounds it so a
/// missed wake can never wedge the channel forever.
#[allow(clippy::duration_suboptimal_units)]
const USB_EDGE_PARK_CEILING: Duration = Duration::from_secs(3600);

/// Watches removable volumes and reports the files written onto them as
/// [`DlpChannel::UsbTransfer`] events.
///
/// A [`UdevMonitor`] delivers the `add` of a new block partition
/// edge-triggered; the monitor confirms the device is removable via
/// sysfs, waits briefly for the kernel/automounter to mount it, then
/// scans the mount with the bounded directory watcher. When the
/// netlink socket is unavailable it falls back to periodically
/// re-reading `/proc/mounts`.
#[derive(Debug)]
pub struct LinuxUsbTransferMonitor {
    detector: LinuxRemovableStorageMonitor,
    watcher: SensitiveDirWatcher,
    /// Pulsed by the udev worker when a removable partition arrives, so
    /// `next_event` wakes immediately rather than on the idle cadence.
    wake: Arc<tokio::sync::Notify>,
    closed: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Whether a udev netlink worker is running. When false the monitor
    /// degrades to a polling cadence.
    edge_triggered: bool,
}

impl LinuxUsbTransferMonitor {
    /// Build a monitor over `detector`, attempting to open the udev
    /// netlink socket for edge-triggered device arrival. A background
    /// thread owns the socket and pulses [`Self::wake`] on each
    /// removable-partition `add`; the async side never blocks on it.
    #[must_use]
    pub fn new(detector: LinuxRemovableStorageMonitor) -> Self {
        let wake = Arc::new(tokio::sync::Notify::new());
        let closed = Arc::new(AtomicBool::new(false));
        let (worker, edge_triggered) = match UdevMonitor::open() {
            Ok(udev) => {
                let wake_w = Arc::clone(&wake);
                let closed_w = Arc::clone(&closed);
                let handle = std::thread::Builder::new()
                    .name("sng-dlp-udev".to_owned())
                    .spawn(move || udev_worker(&udev, &wake_w, &closed_w))
                    .ok();
                (handle, true)
            }
            Err(e) => {
                tracing::info!(
                    target: "sng_pal::dlp",
                    error = %e,
                    "udev netlink unavailable; USB channel will poll /proc/mounts"
                );
                (None, false)
            }
        };
        Self {
            detector,
            watcher: SensitiveDirWatcher::new(DlpChannel::UsbTransfer, Vec::new()),
            wake,
            closed,
            worker: Mutex::new(worker),
            edge_triggered,
        }
    }

    /// Stop the monitor and join the udev worker.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.watcher.shutdown();
        self.wake.notify_one();
        if let Some(handle) = lock(&self.worker).take() {
            let _ = handle.join();
        }
    }

    /// Refresh the watcher's roots to the current removable mounts and
    /// run one scan pass. Returns whether any removable volume is
    /// currently mounted (so the caller can pick its wake cadence).
    fn refresh_and_scan(&self) -> bool {
        let mounts = self.detector.removable_mounts();
        let dirs: Vec<PathBuf> = mounts.into_iter().map(|m| m.mount_point).collect();
        let has_mounts = !dirs.is_empty();
        self.watcher.set_dirs(dirs);
        self.watcher.scan();
        has_mounts
    }
}

impl Drop for LinuxUsbTransferMonitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The udev worker thread: parks on the netlink socket and pulses
/// `wake` whenever a removable block partition is added.
fn udev_worker(udev: &UdevMonitor, wake: &tokio::sync::Notify, closed: &AtomicBool) {
    while !closed.load(Ordering::SeqCst) {
        match udev.next(SHUTDOWN_POLL) {
            Ok(Some(event)) if event.is_block_partition_add() => wake.notify_one(),
            Ok(_) => {}
            Err(_) => break,
        }
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
            // Reading `/proc/mounts` and scanning the (small) removable
            // roots is cheap; do it up front so a device already mounted
            // at start-up — and any files copied onto a still-mounted
            // device since the last pass — are reported.
            let has_mounts = self.refresh_and_scan();
            if let Some(event) = self.watcher.try_pop() {
                return Ok(Some(event));
            }
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            // While a volume is mounted, scan at the watcher cadence to
            // catch an ongoing copy; otherwise park until the udev
            // worker signals an arrival (or the idle fallback elapses
            // when no netlink socket is available).
            let wait = if has_mounts {
                self.watcher.poll_interval()
            } else if self.edge_triggered {
                // Effectively "until notified": a generous ceiling that
                // still bounds the wait should a notify ever be missed.
                USB_EDGE_PARK_CEILING
            } else {
                USB_IDLE_FALLBACK
            };
            tokio::select! {
                () = self.wake.notified() => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Clipboard channel
// ---------------------------------------------------------------------------

/// Reads the desktop clipboard selection.
///
/// On X11 the selection is read natively through [`x11rb`] with an
/// XFIXES edge-trigger; on Wayland it is read through the compositor's
/// `wl-paste` data bridge. The chosen transport is decided once at
/// construction from the environment.
#[derive(Debug)]
pub struct LinuxClipboardMonitor {
    inner: ClipboardInner,
}

#[derive(Debug)]
enum ClipboardInner {
    X11(x11::X11ClipboardMonitor),
    Wayland(WaylandClipboardMonitor),
    Unavailable,
}

impl Default for LinuxClipboardMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxClipboardMonitor {
    /// Select the clipboard transport from the environment: native X11
    /// when `DISPLAY` is set, the Wayland data bridge when only
    /// `WAYLAND_DISPLAY` is, else unavailable.
    #[must_use]
    pub fn new() -> Self {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let x11_display = std::env::var_os("DISPLAY").is_some();
        let inner = if x11_display {
            match x11::X11ClipboardMonitor::connect() {
                Ok(monitor) => ClipboardInner::X11(monitor),
                Err(reason) => {
                    tracing::info!(
                        target: "sng_pal::dlp",
                        %reason,
                        "X11 clipboard connect failed; trying Wayland bridge"
                    );
                    if wayland {
                        ClipboardInner::Wayland(WaylandClipboardMonitor::new())
                    } else {
                        ClipboardInner::Unavailable
                    }
                }
            }
        } else if wayland {
            ClipboardInner::Wayland(WaylandClipboardMonitor::new())
        } else {
            ClipboardInner::Unavailable
        };
        Self { inner }
    }

    /// Tear the monitor down; the next [`next_event`](ChannelInterceptor::next_event)
    /// returns `Ok(None)`.
    pub fn shutdown(&self) {
        match &self.inner {
            ClipboardInner::X11(m) => m.shutdown(),
            ClipboardInner::Wayland(m) => m.shutdown(),
            ClipboardInner::Unavailable => {}
        }
    }
}

#[async_trait]
impl ChannelInterceptor for LinuxClipboardMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Clipboard
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        match &self.inner {
            ClipboardInner::X11(m) => m.next_event().await,
            ClipboardInner::Wayland(m) => m.next_event().await,
            ClipboardInner::Unavailable => Err(ChannelError::Unavailable(
                "no X11 or Wayland display".to_owned(),
            )),
        }
    }
}

/// Build the metadata stamped on a clipboard content event.
fn clipboard_metadata() -> ContentMetadata {
    ContentMetadata {
        filename: None,
        content_type: Some("text/plain".to_owned()),
        source: Some("clipboard".to_owned()),
        mip_labels: Vec::new(),
        ..ContentMetadata::default()
    }
}

/// Wayland clipboard reader. Wayland deliberately denies an unfocused
/// client direct access to the clipboard, so the portable native path
/// is the compositor's own `wl-paste` data bridge (part of
/// `wl-clipboard`). Reads are driven on demand by the agent's
/// focus/selection signal; [`shutdown`](Self::shutdown) makes a
/// subsequent read return `Ok(None)`.
#[derive(Debug, Default)]
struct WaylandClipboardMonitor {
    closed: AtomicBool,
    last_hash: Mutex<Option<u64>>,
}

impl WaylandClipboardMonitor {
    fn new() -> Self {
        Self::default()
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn read_selection() -> Result<Vec<u8>, ChannelError> {
        match Command::new("wl-paste").arg("--no-newline").output() {
            Ok(out) if out.status.success() => Ok(out.stdout),
            Ok(out) => Err(ChannelError::Init(format!(
                "wl-paste exited with status {}",
                out.status
            ))),
            Err(e) => Err(ChannelError::Unavailable(format!(
                "wl-paste unavailable: {e}"
            ))),
        }
    }
}

#[async_trait]
impl ChannelInterceptor for WaylandClipboardMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Clipboard
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let content = Self::read_selection()?;
        // Dedup: only surface a selection that differs from the last one
        // we reported, so a consumer that loops does not re-inspect an
        // unchanged clipboard.
        let hash = content_hash(&content);
        {
            let mut last = lock(&self.last_hash);
            if *last == Some(hash) {
                return Ok(Some(ContentEvent {
                    channel: DlpChannel::Clipboard,
                    content: Vec::new(),
                    metadata: clipboard_metadata(),
                }));
            }
            *last = Some(hash);
        }
        Ok(Some(ContentEvent {
            channel: DlpChannel::Clipboard,
            content,
            metadata: clipboard_metadata(),
        }))
    }
}

/// FNV-1a hash for clipboard-selection dedup. Not cryptographic; only
/// used to detect "the selection changed since we last read it".
fn content_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Native X11 clipboard backend (its own module so the x11rb protocol
/// types stay scoped).
mod x11 {
    use super::{
        ChannelError, ContentEvent, DlpChannel, clipboard_metadata, content_hash, lock,
        poll_timeout,
    };
    use async_trait::async_trait;
    use sng_dlp::ChannelInterceptor;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;
    use x11rb::connection::Connection;
    use x11rb::protocol::Event;
    use x11rb::protocol::xfixes::{ConnectionExt as _, SelectionEventMask};
    use x11rb::protocol::xproto::{
        Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, WindowClass,
    };
    use x11rb::rust_connection::RustConnection;

    /// Per-file read ceiling for a clipboard selection. A pasteboard is
    /// bounded in practice; this caps a pathological producer.
    const MAX_CLIP_BYTES: u32 = 1024 * 1024;

    /// Shared buffer between the X event-loop thread and the consumer.
    #[derive(Debug, Default)]
    struct Shared {
        buffer: Mutex<std::collections::VecDeque<ContentEvent>>,
        closed: AtomicBool,
        drained: AtomicBool,
    }

    /// Native X11 CLIPBOARD monitor.
    #[derive(Debug)]
    pub(super) struct X11ClipboardMonitor {
        shared: Arc<Shared>,
        worker: Mutex<Option<JoinHandle<()>>>,
    }

    impl X11ClipboardMonitor {
        /// Connect to the X server, arm the XFIXES selection-owner
        /// notification on CLIPBOARD, and spawn the event-loop thread.
        pub(super) fn connect() -> Result<Self, String> {
            let (conn, screen_num) =
                x11rb::connect(None).map_err(|e| format!("x11 connect: {e}"))?;
            let screen = &conn.setup().roots[screen_num];
            let root = screen.root;

            // An InputOnly, unmapped window we own to receive XFIXES
            // notifications and hold the converted-selection property.
            let window = conn.generate_id().map_err(|e| format!("x11 id: {e}"))?;
            conn.create_window(
                0,
                window,
                root,
                0,
                0,
                1,
                1,
                0,
                WindowClass::INPUT_ONLY,
                0,
                &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            )
            .map_err(|e| format!("x11 create_window: {e}"))?;

            // XFIXES is required for selection-owner notifications.
            conn.xfixes_query_version(5, 0)
                .map_err(|e| format!("xfixes query: {e}"))?;

            let clipboard = intern(&conn, b"CLIPBOARD").map_err(|e| format!("intern CLIPBOARD: {e}"))?;
            let utf8 = intern(&conn, b"UTF8_STRING").map_err(|e| format!("intern UTF8: {e}"))?;
            let target_prop =
                intern(&conn, b"SNG_DLP_CLIP").map_err(|e| format!("intern prop: {e}"))?;

            conn.xfixes_select_selection_input(
                window,
                clipboard,
                SelectionEventMask::SET_SELECTION_OWNER
                    | SelectionEventMask::SELECTION_CLIENT_CLOSE
                    | SelectionEventMask::SELECTION_WINDOW_DESTROY,
            )
            .map_err(|e| format!("xfixes select input: {e}"))?;
            conn.flush().map_err(|e| format!("x11 flush: {e}"))?;

            let shared = Arc::new(Shared::default());
            let worker_shared = Arc::clone(&shared);
            let atoms = Atoms {
                clipboard,
                utf8,
                target_prop,
                window,
            };
            let worker = std::thread::Builder::new()
                .name("sng-dlp-x11-clip".to_owned())
                .spawn(move || event_loop(conn, atoms, &worker_shared))
                .map_err(|e| format!("spawn x11 worker: {e}"))?;

            Ok(Self {
                shared,
                worker: Mutex::new(Some(worker)),
            })
        }

        pub(super) fn shutdown(&self) {
            self.shared.closed.store(true, Ordering::SeqCst);
            if let Some(handle) = lock(&self.worker).take() {
                let _ = handle.join();
            }
        }
    }

    impl Drop for X11ClipboardMonitor {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    #[async_trait]
    impl ChannelInterceptor for X11ClipboardMonitor {
        fn channel(&self) -> DlpChannel {
            DlpChannel::Clipboard
        }
        async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
            loop {
                if let Some(event) = lock(&self.shared.buffer).pop_front() {
                    return Ok(Some(event));
                }
                if self.shared.closed.load(Ordering::SeqCst)
                    || self.shared.drained.load(Ordering::SeqCst)
                {
                    if let Some(event) = lock(&self.shared.buffer).pop_front() {
                        return Ok(Some(event));
                    }
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    #[derive(Clone, Copy)]
    struct Atoms {
        clipboard: Atom,
        utf8: Atom,
        target_prop: Atom,
        window: u32,
    }

    fn intern(conn: &RustConnection, name: &[u8]) -> Result<Atom, Box<dyn std::error::Error>> {
        Ok(conn.intern_atom(false, name)?.reply()?.atom)
    }

    /// The X event loop. Blocks in `wait_for_event`; on an XFIXES
    /// selection-owner change it asks the owner to convert CLIPBOARD to
    /// UTF8_STRING into our property, then on the resulting
    /// SelectionNotify reads the property and queues a content event.
    /// Dedups identical consecutive selections.
    //
    // `conn` is taken by value: the loop owns the X connection for the
    // whole thread lifetime and closes it on return.
    #[allow(clippy::needless_pass_by_value)]
    fn event_loop(conn: RustConnection, atoms: Atoms, shared: &Shared) {
        let mut last_hash: Option<u64> = None;
        loop {
            if shared.closed.load(Ordering::SeqCst) {
                break;
            }
            // `wait_for_event` blocks; to keep shutdown responsive we
            // poll for an event with a short timeout via the poll-then-
            // poll_for_event pattern.
            let event = match next_event_timeout(&conn) {
                Ok(Some(ev)) => ev,
                Ok(None) => continue,
                Err(_) => break,
            };
            match event {
                Event::XfixesSelectionNotify(ev) if ev.selection == atoms.clipboard => {
                    // Owner changed: request a conversion. The reply
                    // arrives as a core SelectionNotify below.
                    let _ = conn.convert_selection(
                        atoms.window,
                        atoms.clipboard,
                        atoms.utf8,
                        atoms.target_prop,
                        ev.timestamp,
                    );
                    let _ = conn.flush();
                }
                Event::SelectionNotify(ev) if ev.property != u32::from(AtomEnum::NONE) => {
                    if let Some(bytes) = read_property(&conn, atoms) {
                        let hash = content_hash(&bytes);
                        if last_hash != Some(hash) {
                            last_hash = Some(hash);
                            lock(&shared.buffer).push_back(ContentEvent {
                                channel: DlpChannel::Clipboard,
                                content: bytes,
                                metadata: clipboard_metadata(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        shared.drained.store(true, Ordering::SeqCst);
    }

    /// Wait up to ~500ms for the next X event, returning `Ok(None)` on
    /// timeout so the loop can re-check the shutdown flag.
    fn next_event_timeout(
        conn: &RustConnection,
    ) -> Result<Option<Event>, x11rb::rust_connection::ReplyOrIdError> {
        use nix::poll::{PollFd, PollFlags};
        use std::os::fd::AsFd;
        // Drain anything already buffered without blocking.
        if let Some(ev) = conn.poll_for_event()? {
            return Ok(Some(ev));
        }
        let borrowed = conn.stream().as_fd();
        let mut fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
        match nix::poll::poll(&mut fds, poll_timeout(Duration::from_millis(500))) {
            // Timeout or poll error: no event this round, re-check shutdown.
            Ok(0) | Err(_) => Ok(None),
            Ok(_) => Ok(conn.poll_for_event()?),
        }
    }

    /// Read the converted selection from our property and delete it.
    fn read_property(conn: &RustConnection, atoms: Atoms) -> Option<Vec<u8>> {
        let reply = conn
            .get_property(
                true, // delete after read
                atoms.window,
                atoms.target_prop,
                AtomEnum::ANY,
                0,
                MAX_CLIP_BYTES / 4, // length is in 32-bit units
            )
            .ok()?
            .reply()
            .ok()?;
        if reply.value.is_empty() {
            return None;
        }
        Some(reply.value)
    }
}
