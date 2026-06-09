//! macOS endpoint-DLP `ChannelInterceptor` backends.
//!
//! These bind the stable, documented macOS C frameworks directly —
//! no Objective-C runtime crate graph — keeping the dependency surface
//! to the single `libc` crate the rest of the macOS PAL already uses:
//!
//! * **File write / Print / USB** — [`MacFileWriteMonitor`],
//!   [`MacPrintMonitor`] and [`MacUsbTransferMonitor`] are driven by
//!   **FSEvents** (`FSEventStreamCreate` + a libdispatch queue). The
//!   stream is created with `kFSEventStreamCreateFlagFileEvents` so the
//!   kernel reports file-level create/modify/rename events with their
//!   paths; the callback reads the (bounded) file content and queues a
//!   [`ContentEvent`]. This is edge-triggered: the agent sleeps until
//!   the kernel wakes the dispatch queue, never polling the tree. If
//!   the stream cannot be created the backend falls back to the
//!   portable [`SensitiveDirWatcher`] so coverage is never lost.
//! * **Clipboard** — [`MacClipboardMonitor`] reads the general
//!   pasteboard through the **Pasteboard Manager** (HIServices:
//!   `PasteboardCreate` / `PasteboardSynchronize` /
//!   `PasteboardCopyItemFlavorData`). macOS exposes no pasteboard
//!   change notification — the OS-native idiom (used by AppKit's own
//!   `NSPasteboard.changeCount`) is to compare the change count; here
//!   `PasteboardSynchronize`'s `kPasteboardModified` flag plays that
//!   role, so a read only happens when the selection actually changed.
//!
//! ## Kernel-facility boundary (EndpointSecurity)
//!
//! Apple's **EndpointSecurity** kernel-auth API can only run inside a
//! separately-signed *System Extension* process carrying the
//! `com.apple.developer.endpoint-security.client` entitlement — it
//! cannot be hosted inside a general-purpose user-mode library such as
//! this PAL crate. The correct long-term architecture is therefore an
//! ES System Extension that forwards file-auth events to the agent over
//! XPC; the in-process file channel here uses FSEvents, the highest-
//! fidelity facility available without that entitlement. The ES
//! extension is delivered as its own signed bundle, out of scope for
//! this crate.
//
// SAFETY (module-wide `allow(unsafe_code)`): every `unsafe` block below
// is a call into a documented, stable macOS C framework
// (CoreFoundation, CoreServices/FSEvents, ApplicationServices/
// HIServices) or a pointer round-trip for an FSEvents callback's
// `info` context. The bindings mirror the public framework headers
// exactly (verified field-for-field against `<CoreServices/...>` and
// `<HIServices/Pasteboard.h>`); no struct layout is invented. Ownership
// of every CoreFoundation object created here is released on the same
// path (`CFRelease`), and the FSEvents `info` pointer is an
// `Arc::into_raw` that is reclaimed in `Drop`.
#![allow(unsafe_code)]

use super::{FileWatchOptions, SensitiveDirWatcher, lock, mime_for_path};
use async_trait::async_trait;
use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
use std::collections::VecDeque;
use std::ffi::{CStr, OsStr, c_char, c_void};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Cadence at which `next_event` drains the FSEvents buffer or re-reads
/// the pasteboard change count. The FSEvents path is edge-triggered —
/// this only bounds how quickly a queued event is surfaced and how
/// responsive shutdown is, not how often the kernel is asked.
const DRAIN_TICK: Duration = Duration::from_millis(100);

/// Pasteboard poll cadence. The pasteboard has no change notification;
/// AppKit apps themselves poll the change count, so this is the native
/// idiom rather than a busy loop over content.
const CLIPBOARD_TICK: Duration = Duration::from_millis(700);

/// Default directories watched for sensitive-file writes when policy
/// does not override them.
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
// FFI: CoreFoundation / CoreServices (FSEvents) / libdispatch
// ---------------------------------------------------------------------------

mod ffi {
    // Raw framework bindings used only by the parent `macos` module;
    // `pub` here is module-internal, never part of the crate surface.
    #![allow(unreachable_pub)]
    use std::ffi::{c_char, c_void};

    pub type CFAllocatorRef = *const c_void;
    pub type CFTypeRef = *const c_void;
    pub type CFStringRef = *const c_void;
    pub type CFDataRef = *const c_void;
    pub type CFArrayRef = *const c_void;
    pub type CFIndex = isize;
    pub type Boolean = u8;
    pub type OSStatus = i32;
    pub type CFTimeInterval = f64;

    pub type FSEventStreamRef = *mut c_void;
    pub type ConstFSEventStreamRef = *const c_void;
    pub type FSEventStreamEventId = u64;
    pub type FSEventStreamCreateFlags = u32;
    pub type FSEventStreamEventFlags = u32;
    pub type DispatchQueueT = *mut c_void;

    // Pasteboard Manager (HIServices).
    pub type PasteboardRef = *mut c_void;
    pub type PasteboardItemID = *mut c_void;
    pub type PasteboardSyncFlags = u32;
    pub type ItemCount = u64;

    /// `kCFStringEncodingUTF8`.
    pub const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    /// Report file-level (not directory-level) events with paths.
    pub const FILE_EVENTS: FSEventStreamCreateFlags = 0x0000_0010;
    /// Deliver events as soon as they occur (no extra coalescing delay).
    pub const NO_DEFER: FSEventStreamCreateFlags = 0x0000_0002;
    /// `kFSEventStreamEventIdSinceNow`.
    pub const SINCE_NOW: FSEventStreamEventId = u64::MAX;

    pub const FLAG_ITEM_IS_FILE: FSEventStreamEventFlags = 0x0001_0000;
    pub const FLAG_ITEM_CREATED: FSEventStreamEventFlags = 0x0000_0100;
    pub const FLAG_ITEM_MODIFIED: FSEventStreamEventFlags = 0x0000_1000;
    pub const FLAG_ITEM_RENAMED: FSEventStreamEventFlags = 0x0000_0800;

    /// The pasteboard changed since the previous synchronize.
    pub const PASTEBOARD_MODIFIED: PasteboardSyncFlags = 0x0000_0001;

    #[repr(C)]
    pub struct FSEventStreamContext {
        pub version: CFIndex,
        pub info: *mut c_void,
        pub retain: Option<extern "C" fn(*const c_void) -> *const c_void>,
        pub release: Option<extern "C" fn(*const c_void)>,
        pub copy_description: Option<extern "C" fn(*const c_void) -> CFStringRef>,
    }

    pub type FSEventStreamCallback = extern "C" fn(
        stream: ConstFSEventStreamRef,
        info: *mut c_void,
        num_events: usize,
        event_paths: *mut c_void,
        event_flags: *const FSEventStreamEventFlags,
        event_ids: *const FSEventStreamEventId,
    );

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        pub fn CFRelease(cf: CFTypeRef);
        pub fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: u32,
            is_external: Boolean,
        ) -> CFStringRef;
        pub fn CFArrayCreate(
            alloc: CFAllocatorRef,
            values: *const *const c_void,
            num_values: CFIndex,
            callbacks: *const c_void,
        ) -> CFArrayRef;
        pub fn CFDataGetLength(data: CFDataRef) -> CFIndex;
        pub fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    }

    #[link(name = "CoreServices", kind = "framework")]
    unsafe extern "C" {
        pub fn FSEventStreamCreate(
            allocator: CFAllocatorRef,
            callback: FSEventStreamCallback,
            context: *const FSEventStreamContext,
            paths_to_watch: CFArrayRef,
            since_when: FSEventStreamEventId,
            latency: CFTimeInterval,
            flags: FSEventStreamCreateFlags,
        ) -> FSEventStreamRef;
        pub fn FSEventStreamSetDispatchQueue(stream: FSEventStreamRef, q: DispatchQueueT);
        pub fn FSEventStreamStart(stream: FSEventStreamRef) -> Boolean;
        pub fn FSEventStreamStop(stream: FSEventStreamRef);
        pub fn FSEventStreamInvalidate(stream: FSEventStreamRef);
        pub fn FSEventStreamRelease(stream: FSEventStreamRef);
    }

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        pub static kPasteboardClipboard: CFStringRef;
        pub fn PasteboardCreate(name: CFStringRef, out: *mut PasteboardRef) -> OSStatus;
        pub fn PasteboardSynchronize(p: PasteboardRef) -> PasteboardSyncFlags;
        pub fn PasteboardGetItemCount(p: PasteboardRef, out: *mut ItemCount) -> OSStatus;
        pub fn PasteboardGetItemIdentifier(
            p: PasteboardRef,
            index: ItemCount,
            out: *mut PasteboardItemID,
        ) -> OSStatus;
        pub fn PasteboardCopyItemFlavorData(
            p: PasteboardRef,
            item: PasteboardItemID,
            flavor_type: CFStringRef,
            out: *mut CFDataRef,
        ) -> OSStatus;
    }

    // libdispatch lives in libSystem, which is always linked.
    unsafe extern "C" {
        pub fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueueT;
        pub fn dispatch_release(object: DispatchQueueT);
    }
}

/// A CoreFoundation string created from UTF-8 bytes, released on drop.
struct CfString(ffi::CFStringRef);

impl CfString {
    fn new(s: &[u8]) -> Option<Self> {
        // SAFETY: `s`'s pointer/len are valid for the call; CF copies the
        // bytes. A null return (allocation failure) is surfaced as None.
        let cf = unsafe {
            ffi::CFStringCreateWithBytes(
                std::ptr::null(),
                s.as_ptr(),
                ffi::CFIndex::try_from(s.len()).unwrap_or(ffi::CFIndex::MAX),
                ffi::K_CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        if cf.is_null() { None } else { Some(Self(cf)) }
    }
}

impl Drop for CfString {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null CFStringRef we own exactly one
        // reference to (created via CFStringCreateWithBytes).
        unsafe { ffi::CFRelease(self.0) };
    }
}

// ---------------------------------------------------------------------------
// FSEvents watcher
// ---------------------------------------------------------------------------

/// State shared between the FSEvents callback (run on a libdispatch
/// queue) and the async `next_event` consumer.
#[derive(Debug)]
struct FsShared {
    buffer: Mutex<VecDeque<ContentEvent>>,
    closed: AtomicBool,
    channel: DlpChannel,
    max_file_bytes: usize,
}

/// An FSEvents stream watching a set of roots, delivering file-level
/// events to a libdispatch queue. Edge-triggered: the agent is woken by
/// the kernel rather than polling the tree.
struct FsEventsWatcher {
    shared: Arc<FsShared>,
    /// `FSEventStreamRef` as an integer so the handle is `Send`; it is
    /// only ever touched (start/stop/invalidate/release) from the owning
    /// monitor, serialised by `&mut self` / `Drop`.
    stream: usize,
}

// SAFETY: the `stream` handle is only used for start/stop/invalidate/
// release, all issued from the owning monitor (never concurrently). The
// callback receives its state through the `Arc<FsShared>` info pointer,
// which is itself `Send + Sync`.
unsafe impl Send for FsEventsWatcher {}
unsafe impl Sync for FsEventsWatcher {}

impl std::fmt::Debug for FsEventsWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsEventsWatcher")
            .field("channel", &self.shared.channel)
            .finish_non_exhaustive()
    }
}

/// FSEvents callback. Reads each created/modified/renamed regular file
/// (bounded) and queues it as a content event.
extern "C" fn fsevents_callback(
    _stream: ffi::ConstFSEventStreamRef,
    info: *mut c_void,
    num_events: usize,
    event_paths: *mut c_void,
    event_flags: *const ffi::FSEventStreamEventFlags,
    _event_ids: *const ffi::FSEventStreamEventId,
) {
    // SAFETY: `info` is the `Arc<FsShared>` pointer handed to
    // FSEventStreamCreate via the context; we borrow it without taking
    // ownership (the Arc is reclaimed in Drop). `event_paths` is a
    // `char *[num_events]` (FileEvents flag, no UseCFTypes), and
    // `event_flags` is a parallel `num_events`-long array — exactly the
    // FSEvents callback contract.
    let shared = unsafe { &*(info as *const FsShared) };
    if shared.closed.load(Ordering::SeqCst) {
        return;
    }
    let paths = event_paths as *const *const c_char;
    for i in 0..num_events {
        // SAFETY: indices are bounded by `num_events`, the documented
        // length of both parallel arrays.
        let flags = unsafe { *event_flags.add(i) };
        let is_file = flags & ffi::FLAG_ITEM_IS_FILE != 0;
        let touched = flags
            & (ffi::FLAG_ITEM_CREATED | ffi::FLAG_ITEM_MODIFIED | ffi::FLAG_ITEM_RENAMED)
            != 0;
        if !is_file || !touched {
            continue;
        }
        // SAFETY: each entry is a NUL-terminated C string owned by
        // FSEvents for the duration of the callback.
        let c_path = unsafe { *paths.add(i) };
        if c_path.is_null() {
            continue;
        }
        let c_str = unsafe { CStr::from_ptr(c_path) };
        let path = PathBuf::from(OsStr::from_bytes(c_str.to_bytes()));
        if let Some(event) = read_file_event(&path, shared.channel, shared.max_file_bytes) {
            lock(&shared.buffer).push_back(event);
        }
    }
}

impl FsEventsWatcher {
    /// Start an FSEvents stream over `roots`. Returns `Err` if no root
    /// is usable or the stream/queue cannot be created, so the caller
    /// can fall back to the portable poll watcher.
    fn start(
        channel: DlpChannel,
        roots: &[PathBuf],
        max_file_bytes: usize,
    ) -> Result<Self, String> {
        let roots: Vec<&Path> = roots
            .iter()
            .filter(|p| p.exists())
            .map(PathBuf::as_path)
            .collect();
        if roots.is_empty() {
            return Err("no watchable root".to_owned());
        }

        // Build a CFArray<CFString> of the paths. The CfStrings are kept
        // alive until after FSEventStreamCreate copies them.
        let cf_paths: Vec<CfString> = roots
            .iter()
            .filter_map(|p| CfString::new(p.as_os_str().as_bytes()))
            .collect();
        if cf_paths.len() != roots.len() {
            return Err("path encode failed".to_owned());
        }
        let raw: Vec<*const c_void> = cf_paths.iter().map(|s| s.0).collect();
        // SAFETY: `raw` is a valid `len`-long array of CFStringRefs;
        // passing null callbacks means the array does not retain/release
        // its members — fine, as the CfStrings outlive this call.
        let array = unsafe {
            ffi::CFArrayCreate(
                std::ptr::null(),
                raw.as_ptr(),
                ffi::CFIndex::try_from(raw.len()).unwrap_or(0),
                std::ptr::null(),
            )
        };
        if array.is_null() {
            return Err("CFArrayCreate failed".to_owned());
        }

        let shared = Arc::new(FsShared {
            buffer: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            channel,
            max_file_bytes,
        });
        let info = Arc::into_raw(Arc::clone(&shared)) as *mut c_void;
        let context = ffi::FSEventStreamContext {
            version: 0,
            info,
            retain: None,
            release: None,
            copy_description: None,
        };

        // SAFETY: documented FSEventStreamCreate call; `context` and
        // `array` are valid for the call. On success FSEvents copies the
        // paths, so the CFArray + CfStrings can be released afterwards.
        let stream = unsafe {
            ffi::FSEventStreamCreate(
                std::ptr::null(),
                fsevents_callback,
                &raw const context,
                array,
                ffi::SINCE_NOW,
                0.2_f64,
                ffi::FILE_EVENTS | ffi::NO_DEFER,
            )
        };
        // SAFETY: we own one ref to `array`.
        unsafe { ffi::CFRelease(array) };
        drop(cf_paths);

        if stream.is_null() {
            // Reclaim the Arc ref we leaked into `info`.
            // SAFETY: `info` came from Arc::into_raw above.
            unsafe { drop(Arc::from_raw(info as *const FsShared)) };
            return Err("FSEventStreamCreate failed".to_owned());
        }

        // A serial dispatch queue drives the callback off the agent's
        // runtime threads. It lives for the monitor's lifetime (created
        // once at start-up); the stream retains it until invalidated.
        let label = c"com.sng.dlp.fsevents";
        // SAFETY: a static C string label; null attr => serial queue.
        let queue = unsafe { ffi::dispatch_queue_create(label.as_ptr(), std::ptr::null()) };
        if queue.is_null() {
            // SAFETY: stream is non-null and not yet scheduled/started.
            unsafe {
                ffi::FSEventStreamInvalidate(stream);
                ffi::FSEventStreamRelease(stream);
                drop(Arc::from_raw(info as *const FsShared));
            }
            return Err("dispatch_queue_create failed".to_owned());
        }
        // SAFETY: stream + queue are valid; start returns false on
        // failure (e.g. the path set could not be watched).
        let started = unsafe {
            ffi::FSEventStreamSetDispatchQueue(stream, queue);
            // `FSEventStreamSetDispatchQueue` takes its own retain on the
            // queue, so balance the +1 returned by `dispatch_queue_create`
            // now. The stream then owns the sole reference and
            // `FSEventStreamInvalidate` (in `Drop`/teardown) releases it,
            // leaving no leaked dispatch queue across monitor restarts.
            ffi::dispatch_release(queue);
            ffi::FSEventStreamStart(stream) != 0
        };
        if !started {
            // SAFETY: stream valid; tear it down and reclaim the Arc.
            unsafe {
                ffi::FSEventStreamInvalidate(stream);
                ffi::FSEventStreamRelease(stream);
                drop(Arc::from_raw(info as *const FsShared));
            }
            return Err("FSEventStreamStart failed".to_owned());
        }

        Ok(Self {
            shared,
            stream: stream as usize,
        })
    }

    fn try_pop(&self) -> Option<ContentEvent> {
        lock(&self.shared.buffer).pop_front()
    }

    fn shutdown(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
    }
}

impl Drop for FsEventsWatcher {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        let stream = self.stream as ffi::FSEventStreamRef;
        // SAFETY: `stream` was returned by FSEventStreamCreate and
        // started exactly once; stop+invalidate+release is the
        // documented teardown sequence and releases the dispatch queue
        // and the `info` retain installed via the context.
        unsafe {
            ffi::FSEventStreamStop(stream);
            ffi::FSEventStreamInvalidate(stream);
            ffi::FSEventStreamRelease(stream);
            // Reclaim the Arc reference handed to the context `info`.
            drop(Arc::from_raw(Arc::as_ptr(&self.shared).cast::<FsShared>()));
        }
    }
}

/// Read up to `max_file_bytes` of `path` into a content event, or
/// `None` if the file vanished / is unreadable / is not a regular file.
fn read_file_event(
    path: &Path,
    channel: DlpChannel,
    max_file_bytes: usize,
) -> Option<ContentEvent> {
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
// File-write / Print / USB channels (FSEvents-backed)
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum DirInner {
    FsEvents(FsEventsWatcher),
    Poll(SensitiveDirWatcher),
}

impl DirInner {
    fn start(channel: DlpChannel, dirs: Vec<PathBuf>, warm: bool, opts: FileWatchOptions) -> Self {
        match FsEventsWatcher::start(channel, &dirs, opts.max_file_bytes) {
            Ok(w) => DirInner::FsEvents(w),
            Err(reason) => {
                tracing::info!(
                    target: "sng_pal::dlp",
                    %reason,
                    "FSEvents unavailable; falling back to poll watcher"
                );
                let w = SensitiveDirWatcher::new(channel, dirs)
                    .with_max_file_bytes(opts.max_file_bytes)
                    .with_poll_interval(opts.poll_interval);
                DirInner::Poll(if warm { w.warm_started() } else { w })
            }
        }
    }

    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        match self {
            DirInner::FsEvents(w) => loop {
                if let Some(e) = w.try_pop() {
                    return Ok(Some(e));
                }
                if w.shared.closed.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                tokio::time::sleep(DRAIN_TICK).await;
            },
            DirInner::Poll(w) => w.next_event().await,
        }
    }

    fn shutdown(&self) {
        match self {
            DirInner::FsEvents(w) => w.shutdown(),
            DirInner::Poll(w) => w.shutdown(),
        }
    }
}

/// macOS file-write monitor (FSEvents, poll fallback).
#[derive(Debug)]
pub struct MacFileWriteMonitor {
    inner: DirInner,
}

impl MacFileWriteMonitor {
    /// Watch `dirs` (empty → the default sensitive set) with the
    /// default [`FileWatchOptions`].
    #[must_use]
    pub fn new(dirs: Vec<PathBuf>) -> Self {
        Self::with_options(dirs, FileWatchOptions::default())
    }

    /// Watch `dirs` (empty → the default sensitive set) with explicit
    /// operator tuning, so the operator-configured read ceiling and poll
    /// cadence are honoured on macOS exactly as they are on Linux.
    #[must_use]
    pub fn with_options(dirs: Vec<PathBuf>, opts: FileWatchOptions) -> Self {
        let dirs = if dirs.is_empty() {
            default_sensitive_dirs()
        } else {
            dirs
        };
        Self {
            inner: DirInner::start(DlpChannel::FileWrite, dirs, true, opts),
        }
    }

    /// Stop the monitor.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for MacFileWriteMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::FileWrite
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        self.inner.next_event().await
    }
}

/// macOS print monitor — watches the CUPS spool directory via FSEvents.
#[derive(Debug)]
pub struct MacPrintMonitor {
    inner: DirInner,
}

impl MacPrintMonitor {
    /// Watch `spool_dir` (default `/private/var/spool/cups`).
    /// `opts.max_file_bytes` bounds how much of each spooled job is read and
    /// `opts.poll_interval` is honoured on the portable poll fallback, so the
    /// operator's tuning applies to the print channel regardless of backend.
    #[must_use]
    pub fn new(spool_dir: Option<PathBuf>, opts: FileWatchOptions) -> Self {
        let dir = spool_dir.unwrap_or_else(|| PathBuf::from("/private/var/spool/cups"));
        // `warm = true`: the FSEvents native path only reports jobs spooled
        // *after* the stream is armed, so the poll fallback must likewise
        // treat jobs already in the spool at startup as the watermark rather
        // than re-reporting them as fresh prints. Keeps the two transports
        // observably identical (see mod.rs) and matches the Linux print path.
        Self {
            inner: DirInner::start(DlpChannel::Print, vec![dir], true, opts),
        }
    }

    /// Stop the monitor.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for MacPrintMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Print
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        self.inner.next_event().await
    }
}

/// macOS USB-transfer monitor.
///
/// Removable volumes mount under `/Volumes` (the boot volume is at `/`,
/// so it is excluded); an FSEvents stream rooted there reports files
/// written onto any attached volume as [`DlpChannel::UsbTransfer`]
/// events, edge-triggered. When `/Volumes` cannot be watched it falls
/// back to the portable poll watcher.
#[derive(Debug)]
pub struct MacUsbTransferMonitor {
    inner: DirInner,
}

impl Default for MacUsbTransferMonitor {
    fn default() -> Self {
        Self::new(FileWatchOptions::default())
    }
}

impl MacUsbTransferMonitor {
    /// Watch `/Volumes` for writes onto mounted external media.
    /// `opts.max_file_bytes` bounds how much of each file is read and
    /// `opts.poll_interval` is honoured on the portable poll fallback, so the
    /// operator's tuning applies to the USB channel regardless of backend.
    #[must_use]
    pub fn new(opts: FileWatchOptions) -> Self {
        Self {
            inner: DirInner::start(
                DlpChannel::UsbTransfer,
                vec![PathBuf::from("/Volumes")],
                true,
                opts,
            ),
        }
    }

    /// Stop the monitor.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for MacUsbTransferMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::UsbTransfer
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        self.inner.next_event().await
    }
}

// ---------------------------------------------------------------------------
// Clipboard channel (Pasteboard Manager)
// ---------------------------------------------------------------------------

/// macOS clipboard monitor — reads the general pasteboard through the
/// Pasteboard Manager and reports the UTF-8 selection when it changes.
#[derive(Debug)]
pub struct MacClipboardMonitor {
    inner: ClipboardInner,
    closed: Arc<AtomicBool>,
    last_hash: Mutex<Option<u64>>,
}

#[derive(Debug)]
enum ClipboardInner {
    /// Native Pasteboard Manager handle (raw `PasteboardRef` as an
    /// integer so the monitor is `Send`; touched only under `&self`,
    /// serialised by the agent's single consumer per channel).
    Pasteboard(usize),
    /// `pbpaste` fallback when the pasteboard cannot be created.
    PbPaste,
}

// SAFETY: the `PasteboardRef` is only used from `next_event`, which the
// agent calls from a single task per channel; the Pasteboard Manager
// calls used here (`Synchronize`/`GetItemCount`/`Copy…`) are read-only
// and thread-safe for a single owner.
unsafe impl Send for MacClipboardMonitor {}
unsafe impl Sync for MacClipboardMonitor {}

impl Default for MacClipboardMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl MacClipboardMonitor {
    /// A new, open clipboard monitor. Prefers the native pasteboard;
    /// falls back to `pbpaste` if it cannot be created.
    #[must_use]
    pub fn new() -> Self {
        let inner = if let Some(p) = create_general_pasteboard() {
            ClipboardInner::Pasteboard(p as usize)
        } else {
            tracing::info!(
                target: "sng_pal::dlp",
                "pasteboard unavailable; clipboard channel will use pbpaste"
            );
            ClipboardInner::PbPaste
        };
        Self {
            inner,
            closed: Arc::new(AtomicBool::new(false)),
            last_hash: Mutex::new(None),
        }
    }

    /// Tear the monitor down; the next `next_event` returns `Ok(None)`.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// Deduplicate a freshly-read selection: drop it if empty or
    /// unchanged since the last reported value, otherwise record it as
    /// the new watermark and return it.
    fn dedup(&self, bytes: Vec<u8>) -> Option<Vec<u8>> {
        if bytes.is_empty() {
            return None;
        }
        let hash = super::content_hash(&bytes);
        let mut last = lock(&self.last_hash);
        if *last == Some(hash) {
            return None;
        }
        *last = Some(hash);
        Some(bytes)
    }
}

#[async_trait]
impl ChannelInterceptor for MacClipboardMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Clipboard
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let raw = match &self.inner {
                // In-process Pasteboard Manager read — a cheap FFI call,
                // and the raw `PasteboardRef` is not `Send`, so it runs
                // inline.
                ClipboardInner::Pasteboard(p) => read_pasteboard_utf8(*p as ffi::PasteboardRef),
                // `pbpaste` is a blocking subprocess; run it on a
                // blocking thread so the tokio runtime worker is never
                // parked on it.
                ClipboardInner::PbPaste => tokio::task::spawn_blocking(read_pbpaste)
                    .await
                    .unwrap_or(None),
            };
            if let Some(bytes) = raw.and_then(|b| self.dedup(b)) {
                return Ok(Some(ContentEvent {
                    channel: DlpChannel::Clipboard,
                    content: bytes,
                    metadata: super::clipboard_metadata(),
                }));
            }
            tokio::time::sleep(CLIPBOARD_TICK).await;
        }
    }
}

impl Drop for MacClipboardMonitor {
    fn drop(&mut self) {
        if let ClipboardInner::Pasteboard(p) = self.inner {
            // SAFETY: `p` is a PasteboardRef we created and own one ref to.
            unsafe { ffi::CFRelease(p as ffi::CFTypeRef) };
        }
    }
}

/// Create a handle to the general (clipboard) pasteboard.
fn create_general_pasteboard() -> Option<ffi::PasteboardRef> {
    let mut pb: ffi::PasteboardRef = std::ptr::null_mut();
    // SAFETY: `kPasteboardClipboard` is the framework-provided name
    // constant; `&mut pb` receives the created reference. A non-zero
    // OSStatus or null handle is treated as failure.
    let status = unsafe { ffi::PasteboardCreate(ffi::kPasteboardClipboard, &raw mut pb) };
    if status != 0 || pb.is_null() {
        return None;
    }
    Some(pb)
}

/// Read the first UTF-8 plain-text item of the pasteboard if it changed
/// since the last synchronize, returning its bytes.
fn read_pasteboard_utf8(pb: ffi::PasteboardRef) -> Option<Vec<u8>> {
    // SAFETY: `pb` is a valid PasteboardRef owned by the caller.
    let flags = unsafe { ffi::PasteboardSynchronize(pb) };
    if flags & ffi::PASTEBOARD_MODIFIED == 0 {
        // Unchanged since last read; dedup at the change-count level.
        return None;
    }
    let mut count: ffi::ItemCount = 0;
    // SAFETY: valid handle; out-param receives the item count.
    if unsafe { ffi::PasteboardGetItemCount(pb, &raw mut count) } != 0 || count == 0 {
        return None;
    }
    // Pasteboard items are 1-indexed.
    let mut item: ffi::PasteboardItemID = std::ptr::null_mut();
    // SAFETY: index 1 is in range (count >= 1); out-param receives the id.
    if unsafe { ffi::PasteboardGetItemIdentifier(pb, 1, &raw mut item) } != 0 {
        return None;
    }
    let flavor = CfString::new(b"public.utf8-plain-text")?;
    let mut data: ffi::CFDataRef = std::ptr::null();
    // SAFETY: valid handle/item/flavor; out-param receives a +1 CFData
    // we release below.
    let status = unsafe { ffi::PasteboardCopyItemFlavorData(pb, item, flavor.0, &raw mut data) };
    if status != 0 || data.is_null() {
        return None;
    }
    // SAFETY: `data` is a valid non-null CFData we own one ref to.
    let bytes = unsafe {
        let len = ffi::CFDataGetLength(data);
        let ptr = ffi::CFDataGetBytePtr(data);
        let out = if ptr.is_null() || len <= 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(ptr, usize::try_from(len).unwrap_or(0)).to_vec()
        };
        ffi::CFRelease(data);
        out
    };
    Some(bytes)
}

/// Fallback pasteboard read via `/usr/bin/pbpaste`.
fn read_pbpaste() -> Option<Vec<u8>> {
    let output = std::process::Command::new("/usr/bin/pbpaste")
        .output()
        .ok()?;
    if output.status.success() {
        Some(output.stdout)
    } else {
        None
    }
}
