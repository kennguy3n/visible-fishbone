//! Windows endpoint-DLP `ChannelInterceptor` backends.
//!
//! Native, edge-triggered Windows sources for the DLP channels, bound
//! directly against the documented Win32 surface through the `windows`
//! crate (no extra FFI graph):
//!
//! * **File write** — [`WindowsFileWriteMonitor`] uses
//!   `ReadDirectoryChangesW` on a directory handle opened with
//!   `FILE_FLAG_BACKUP_SEMANTICS`. A worker thread blocks in the call
//!   and the kernel wakes it with the changed file names, so a quiet
//!   endpoint costs no CPU. Falls back to the portable
//!   [`SensitiveDirWatcher`] poll watcher when the directory handle
//!   cannot be opened.
//! * **Print** — [`WindowsPrintMonitor`] arms the print-spooler change
//!   notification (`FindFirstPrinterChangeNotification` with
//!   `PRINTER_CHANGE_ADD_JOB`) on the local print server and reports a
//!   spooled job as a [`DlpChannel::Print`] event. Falls back to
//!   watching the spool directory.
//! * **USB transfer** — [`WindowsUsbTransferMonitor`] subscribes to the
//!   WMI `Win32_VolumeChangeEvent` arrival notification through the COM
//!   `IWbemServices` surface; on a volume arrival it scans the
//!   removable drives (`GetLogicalDrives` + `GetDriveTypeW ==
//!   DRIVE_REMOVABLE`) for written files. Falls back to polling the
//!   removable drive set.
//! * **Clipboard** — [`WindowsClipboardMonitor`] joins the clipboard
//!   format-listener chain (`AddClipboardFormatListener` on a
//!   message-only window pumping `WM_CLIPBOARDUPDATE`) and reads
//!   `CF_UNICODETEXT` when the selection changes — edge-triggered, no
//!   polling. Falls back to PowerShell `Get-Clipboard`.
//!
//! [`WindowsWfpEgressGuard`] wraps the Windows Filtering Platform
//! engine (`FwpmEngineOpen0`) and installs a dedicated sublayer used by
//! the agent to block network egress on a DLP `Block` verdict. It is an
//! enforcement helper rather than a content interceptor.
//
// SAFETY (module-wide `allow(unsafe_code)`): every `unsafe` block is a
// call into a documented Win32 API through the `windows` crate's
// generated bindings (which carry the correct signatures), or a
// pointer round-trip for a window's `GWLP_USERDATA` / a worker thread's
// handle. Buffer lengths handed to `ReadDirectoryChangesW` and the WMI
// enumerator are sized explicitly, and every opened handle / COM
// interface is released on the owning type's `Drop`.
#![allow(unsafe_code)]

use super::{DEFAULT_MAX_FILE_BYTES, SensitiveDirWatcher, clipboard_metadata, content_hash, lock, mime_for_path};
use async_trait::async_trait;
use sng_dlp::{ChannelError, ChannelInterceptor, ContentEvent, ContentMetadata, DlpChannel};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HGLOBAL, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW_NAME,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, ReadDirectoryChangesW,
};
use windows::Win32::System::IO::CancelIoEx;
use windows::core::{PCWSTR, w};

/// Cadence at which `next_event` drains a worker buffer; the native
/// hooks are edge-triggered, so this only bounds how quickly a queued
/// event surfaces and how responsive shutdown is.
const DRAIN_TICK: Duration = Duration::from_millis(100);

/// Size of the `ReadDirectoryChangesW` notification buffer. Large
/// enough to absorb a burst of writes without overflow yet bounded so
/// the per-watch resident cost stays small.
const RDC_BUFFER_BYTES: usize = 64 * 1024;

/// Default directories watched for sensitive-file writes when policy
/// does not override them.
fn default_sensitive_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let home = PathBuf::from(profile);
        dirs.push(home.join("Documents"));
        dirs.push(home.join("Downloads"));
        dirs.push(home.join("Desktop"));
    }
    if let Some(tmp) = std::env::var_os("TEMP") {
        dirs.push(PathBuf::from(tmp));
    }
    dirs
}

/// Encode `s` as a NUL-terminated UTF-16 buffer for the wide Win32 API.
fn wide(s: &Path) -> Vec<u16> {
    s.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// State shared between a native worker thread and the async consumer.
#[derive(Debug)]
struct ChannelBuffer {
    buffer: Mutex<VecDeque<ContentEvent>>,
    closed: AtomicBool,
}

impl ChannelBuffer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            buffer: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
        })
    }

    fn push(&self, event: ContentEvent) {
        lock(&self.buffer).push_back(event);
    }

    fn pop(&self) -> Option<ContentEvent> {
        lock(&self.buffer).pop_front()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Read up to `DEFAULT_MAX_FILE_BYTES` of `path`, or `None` if it
/// vanished / is unreadable / is not a regular file.
fn read_file_event(path: &Path, channel: DlpChannel) -> Option<ContentEvent> {
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    if file
        .take(DEFAULT_MAX_FILE_BYTES as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return None;
    }
    let metadata = ContentMetadata {
        filename: path.file_name().and_then(|n| n.to_str()).map(ToOwned::to_owned),
        content_type: mime_for_path(path).map(ToOwned::to_owned),
        source: path.parent().and_then(|p| p.to_str()).map(ToOwned::to_owned),
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
// File write — ReadDirectoryChangesW
// ---------------------------------------------------------------------------

/// A single directory handle watched by a `ReadDirectoryChangesW`
/// worker thread.
#[derive(Debug)]
struct RdcWatch {
    /// Raw `HANDLE` value as `isize` so it is `Send`; only used to
    /// cancel/close on shutdown.
    handle: isize,
    worker: Option<JoinHandle<()>>,
    shared: Arc<ChannelBuffer>,
}

impl RdcWatch {
    /// Open `dir` and spawn the blocking watcher. `Err` lets the caller
    /// fall back to the poll watcher.
    fn start(dir: &Path, channel: DlpChannel, shared: &Arc<ChannelBuffer>) -> Result<Self, String> {
        let wpath = wide(dir);
        // SAFETY: `wpath` is a valid NUL-terminated wide string; the
        // share/flags open a directory handle for change monitoring.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wpath.as_ptr()),
                FILE_LIST_DIRECTORY.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .map_err(|e| format!("CreateFileW({}): {e}", dir.display()))?;

        let shared_w = Arc::clone(shared);
        let root = dir.to_path_buf();
        let raw = handle.0 as isize;
        let worker = std::thread::Builder::new()
            .name("sng-dlp-rdc".to_owned())
            .spawn(move || rdc_worker(HANDLE(raw as *mut std::ffi::c_void), &root, channel, &shared_w))
            .map_err(|e| format!("spawn rdc worker: {e}"))?;

        Ok(Self {
            handle: raw,
            worker: Some(worker),
            shared: Arc::clone(shared),
        })
    }
}

impl Drop for RdcWatch {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        let handle = HANDLE(self.handle as *mut std::ffi::c_void);
        // SAFETY: `handle` is the directory handle opened in `start`.
        // Cancelling unblocks the worker's ReadDirectoryChangesW; the
        // worker no longer touches the handle afterwards, so closing it
        // here (once) is sound.
        unsafe {
            let _ = CancelIoEx(handle, None);
            let _ = CloseHandle(handle);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Blocking `ReadDirectoryChangesW` loop. Reports created/modified/
/// renamed regular files under `root`.
fn rdc_worker(handle: HANDLE, root: &Path, channel: DlpChannel, shared: &ChannelBuffer) {
    // `FILE_NOTIFY_INFORMATION` records are DWORD-aligned, so the receive
    // buffer must be 4-byte aligned: a `Vec<u32>` allocation guarantees
    // that, and we view it as bytes for the API call and the walk.
    let mut buf = vec![0u32; RDC_BUFFER_BYTES / 4];
    let buf_len = u32::try_from(RDC_BUFFER_BYTES).unwrap_or(u32::MAX);
    loop {
        if shared.is_closed() {
            return;
        }
        let mut returned: u32 = 0;
        // SAFETY: `buf` is `RDC_BUFFER_BYTES` long; a synchronous call
        // (no overlapped/completion) blocks until a change or until the
        // handle is closed on shutdown, when it returns an error.
        let ok = unsafe {
            ReadDirectoryChangesW(
                handle,
                buf.as_mut_ptr().cast(),
                buf_len,
                true,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                Some(&raw mut returned),
                None,
                None,
            )
        };
        if ok.is_err() || returned == 0 {
            // Handle closed (shutdown) or a transient error: re-check
            // the shutdown flag and either exit or retry.
            if shared.is_closed() {
                return;
            }
            continue;
        }
        // SAFETY: reinterpret the populated prefix as bytes; `buf` is a
        // single allocation of `RDC_BUFFER_BYTES`, so the byte view is
        // in-bounds and the 4-byte alignment is preserved.
        let bytes = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), RDC_BUFFER_BYTES)
        };
        for name in parse_notify_buffer(&bytes[..returned as usize]) {
            let path = root.join(&name);
            if let Some(event) = read_file_event(&path, channel) {
                shared.push(event);
            }
        }
    }
}

/// Walk the `FILE_NOTIFY_INFORMATION` records in a notification buffer,
/// yielding the file name of each create/modify/rename-to entry.
//
// The caller passes a 4-byte-aligned buffer (allocated as `Vec<u32>`),
// which is exactly the alignment `FILE_NOTIFY_INFORMATION` requires, so
// the pointer cast below is sound despite the `*const u8` source type.
#[allow(clippy::cast_ptr_alignment)]
fn parse_notify_buffer(buf: &[u8]) -> Vec<OsString> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() <= buf.len() {
        // SAFETY: bounds checked above; the buffer was populated by
        // ReadDirectoryChangesW, which lays out `FILE_NOTIFY_INFORMATION`
        // records (each 4-byte aligned).
        let info = unsafe { &*(buf.as_ptr().add(offset).cast::<FILE_NOTIFY_INFORMATION>()) };
        let action = info.Action;
        if action == FILE_ACTION_ADDED
            || action == FILE_ACTION_MODIFIED
            || action == FILE_ACTION_RENAMED_NEW_NAME
        {
            let name_len = info.FileNameLength as usize / 2;
            // SAFETY: the name is `name_len` UTF-16 units immediately
            // after the fixed header, within the record.
            let name = unsafe {
                std::slice::from_raw_parts(info.FileName.as_ptr(), name_len)
            };
            out.push(OsString::from_wide(name));
        }
        let next = info.NextEntryOffset as usize;
        if next == 0 {
            break;
        }
        offset += next;
    }
    out
}

#[derive(Debug)]
enum DirInner {
    // `_watches` is never read but must stay alive: dropping an
    // `RdcWatch` closes its directory handle and stops the worker
    // thread, so the vector is held purely for its RAII effect.
    Native {
        _watches: Vec<RdcWatch>,
        shared: Arc<ChannelBuffer>,
    },
    Poll(SensitiveDirWatcher),
}

impl DirInner {
    fn start(channel: DlpChannel, dirs: Vec<PathBuf>, warm: bool) -> Self {
        let shared = ChannelBuffer::new();
        let mut watches = Vec::new();
        for dir in &dirs {
            if !dir.exists() {
                continue;
            }
            match RdcWatch::start(dir, channel, &shared) {
                Ok(w) => watches.push(w),
                Err(reason) => {
                    tracing::info!(target: "sng_pal::dlp", %reason, "ReadDirectoryChangesW unavailable");
                }
            }
        }
        if watches.is_empty() {
            let w = SensitiveDirWatcher::new(channel, dirs);
            DirInner::Poll(if warm { w.warm_started() } else { w })
        } else {
            DirInner::Native {
                _watches: watches,
                shared,
            }
        }
    }

    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        match self {
            DirInner::Native { shared, .. } => loop {
                if let Some(e) = shared.pop() {
                    return Ok(Some(e));
                }
                if shared.is_closed() {
                    return Ok(None);
                }
                tokio::time::sleep(DRAIN_TICK).await;
            },
            DirInner::Poll(w) => w.next_event().await,
        }
    }

    fn shutdown(&self) {
        match self {
            DirInner::Native { shared, .. } => shared.closed.store(true, Ordering::SeqCst),
            DirInner::Poll(w) => w.shutdown(),
        }
    }
}

/// Windows file-write monitor (`ReadDirectoryChangesW`, poll fallback).
#[derive(Debug)]
pub struct WindowsFileWriteMonitor {
    inner: DirInner,
}

impl WindowsFileWriteMonitor {
    /// Watch `dirs` (empty → the default sensitive set).
    #[must_use]
    pub fn new(dirs: Vec<PathBuf>) -> Self {
        let dirs = if dirs.is_empty() { default_sensitive_dirs() } else { dirs };
        Self {
            inner: DirInner::start(DlpChannel::FileWrite, dirs, true),
        }
    }

    /// Stop the monitor.
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for WindowsFileWriteMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::FileWrite
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        self.inner.next_event().await
    }
}

// ---------------------------------------------------------------------------
// USB transfer — WMI Win32_VolumeChangeEvent + removable-drive scan
// ---------------------------------------------------------------------------

/// Windows USB-transfer monitor.
///
/// A WMI notification worker ([`wmi_volume_worker`]) blocks on a
/// `Win32_VolumeChangeEvent` arrival query and pulses the shared
/// buffer's wake flag; `next_event` then scans the removable drives for
/// written files. When WMI cannot be initialised it falls back to
/// polling the removable-drive set on the drain cadence.
#[derive(Debug)]
pub struct WindowsUsbTransferMonitor {
    shared: Arc<ChannelBuffer>,
    arrivals: Arc<std::sync::atomic::AtomicU64>,
    worker: Mutex<Option<JoinHandle<()>>>,
    last_seen_arrivals: Mutex<u64>,
    watcher: SensitiveDirWatcher,
    native: bool,
}

impl Default for WindowsUsbTransferMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsUsbTransferMonitor {
    /// Build a monitor, attempting the WMI arrival subscription.
    #[must_use]
    pub fn new() -> Self {
        let shared = ChannelBuffer::new();
        let arrivals = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let arrivals_w = Arc::clone(&arrivals);
        let shared_w = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("sng-dlp-wmi-usb".to_owned())
            .spawn(move || wmi_volume_worker(&shared_w, &arrivals_w))
            .ok();
        let native = worker.is_some();
        Self {
            shared,
            arrivals,
            worker: Mutex::new(worker),
            last_seen_arrivals: Mutex::new(0),
            watcher: SensitiveDirWatcher::new(DlpChannel::UsbTransfer, Vec::new()),
            native,
        }
    }

    /// Stop the monitor.
    pub fn shutdown(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.watcher.shutdown();
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
    }

    /// Point the watcher at the currently-mounted removable drives and
    /// run one scan pass.
    fn refresh_and_scan(&self) {
        let dirs = removable_drive_roots();
        self.watcher.set_dirs(dirs);
        self.watcher.scan();
    }
}

impl Drop for WindowsUsbTransferMonitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for WindowsUsbTransferMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::UsbTransfer
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        loop {
            if self.shared.is_closed() {
                return Ok(None);
            }
            if let Some(e) = self.shared.pop() {
                return Ok(Some(e));
            }
            // A new arrival (or, in the polling fallback, every tick)
            // triggers a scan of the removable drives.
            let arrivals = self.arrivals.load(Ordering::SeqCst);
            // Scope the guard so it never crosses the await below (the
            // future must stay `Send` for the subsystem's task set).
            let need_scan = {
                let mut last = lock(&self.last_seen_arrivals);
                if !self.native || arrivals != *last {
                    *last = arrivals;
                    true
                } else {
                    false
                }
            };
            if need_scan {
                self.refresh_and_scan();
                if let Some(e) = self.watcher_pop() {
                    return Ok(Some(e));
                }
            }
            tokio::time::sleep(DRAIN_TICK).await;
        }
    }
}

impl WindowsUsbTransferMonitor {
    /// Drain one event the embedded poll watcher queued during a scan.
    fn watcher_pop(&self) -> Option<ContentEvent> {
        // `SensitiveDirWatcher::scan` enqueues into its own buffer;
        // `try_pop` returns the next without awaiting.
        self.watcher.try_pop()
    }
}

/// Enumerate the root paths of all `DRIVE_REMOVABLE` logical drives.
fn removable_drive_roots() -> Vec<PathBuf> {
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    use windows::Win32::System::WindowsProgramming::DRIVE_REMOVABLE;
    // SAFETY: no arguments; returns a bitmask of present drive letters.
    let mask = unsafe { GetLogicalDrives() };
    let mut roots = Vec::new();
    for i in 0u8..26 {
        if mask & (1u32 << i) == 0 {
            continue;
        }
        let letter = char::from(b'A' + i);
        let root = format!("{letter}:\\");
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a valid NUL-terminated wide string.
        let kind = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };
        if kind == DRIVE_REMOVABLE {
            roots.push(PathBuf::from(root));
        }
    }
    roots
}

/// WMI worker: subscribes to `Win32_VolumeChangeEvent` arrival
/// (`EventType = 2`) and increments `arrivals` on each, waking the
/// async consumer to scan. Returns (the thread exits) if WMI cannot be
/// initialised, leaving the monitor in its polling fallback.
fn wmi_volume_worker(shared: &ChannelBuffer, arrivals: &std::sync::atomic::AtomicU64) {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
    use windows::Win32::System::Wmi::{
        IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WbemLocator,
    };
    use windows::core::BSTR;

    // SAFETY: standard COM init for this worker thread; balanced by
    // CoUninitialize before the thread exits.
    let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if hr.is_err() {
        return;
    }
    let result = (|| -> windows::core::Result<()> {
        // SAFETY: documented COM activation of the WbemLocator.
        let locator: IWbemLocator =
            unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)? };
        // SAFETY: connect to the local CIMV2 namespace.
        let services = unsafe {
            locator.ConnectServer(
                &BSTR::from("ROOT\\CIMV2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )?
        };
        // SAFETY: set the default authentication on the proxy so the
        // notification query is permitted.
        unsafe {
            CoSetProxyBlanket(
                &services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                PCWSTR::null(),
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                None,
                EOAC_NONE,
            )?;
        }
        // SAFETY: arrival-only volume-change notification query.
        let enumerator = unsafe {
            services.ExecNotificationQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?
        };
        while !shared.is_closed() {
            let mut objs = [const { None }; 1];
            let mut returned = 0u32;
            // SAFETY: block up to 1s for the next arrival event; the
            // bounded timeout lets the loop observe the shutdown flag.
            let hr = unsafe { enumerator.Next(1000, &mut objs, &raw mut returned) };
            let _ = hr;
            if returned > 0 {
                arrivals.fetch_add(1, Ordering::SeqCst);
            }
            drop(objs);
        }
        Ok(())
    })();
    if let Err(e) = result {
        tracing::info!(target: "sng_pal::dlp", error = %e, "WMI volume subscription unavailable; USB channel will poll");
    }
    // SAFETY: balances the CoInitializeEx above.
    unsafe { CoUninitialize() };
}

// ---------------------------------------------------------------------------
// Print — spooler change notification
// ---------------------------------------------------------------------------

/// Windows print monitor — arms the spooler `PRINTER_CHANGE_ADD_JOB`
/// notification on the local print server and reports each spooled job.
#[derive(Debug)]
pub struct WindowsPrintMonitor {
    shared: Arc<ChannelBuffer>,
    worker: Mutex<Option<JoinHandle<()>>>,
    fallback: Option<DirInner>,
}

impl Default for WindowsPrintMonitor {
    fn default() -> Self {
        Self::new(None)
    }
}

impl WindowsPrintMonitor {
    /// Watch the print spooler. `spool_dir` overrides the fallback
    /// directory (default `%SystemRoot%\System32\spool\PRINTERS`).
    #[must_use]
    pub fn new(spool_dir: Option<PathBuf>) -> Self {
        let shared = ChannelBuffer::new();
        let shared_w = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("sng-dlp-spooler".to_owned())
            .spawn(move || spooler_worker(&shared_w))
            .ok();
        let fallback = if worker.is_some() {
            None
        } else {
            let dir = spool_dir.unwrap_or_else(default_spool_dir);
            Some(DirInner::start(DlpChannel::Print, vec![dir], false))
        };
        Self {
            shared,
            worker: Mutex::new(worker),
            fallback,
        }
    }

    /// Stop the monitor.
    pub fn shutdown(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        if let Some(fb) = &self.fallback {
            fb.shutdown();
        }
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
    }
}

impl Drop for WindowsPrintMonitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for WindowsPrintMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Print
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        if let Some(fb) = &self.fallback {
            return fb.next_event().await;
        }
        loop {
            if let Some(e) = self.shared.pop() {
                return Ok(Some(e));
            }
            if self.shared.is_closed() {
                return Ok(None);
            }
            tokio::time::sleep(DRAIN_TICK).await;
        }
    }
}

/// Default spooler directory.
fn default_spool_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
    root.join("System32").join("spool").join("PRINTERS")
}

/// Spooler-notification worker: blocks on `FindNextPrinterChangeNotification`
/// and reports a `Print` event per spooled job.
fn spooler_worker(shared: &ChannelBuffer) {
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::Graphics::Printing::{
        ClosePrinter, FindClosePrinterChangeNotification, FindFirstPrinterChangeNotification,
        FindNextPrinterChangeNotification, OpenPrinterW, PRINTER_CHANGE_ADD_JOB, PRINTER_HANDLE,
    };
    use windows::Win32::System::Threading::WaitForSingleObject;

    let mut printer = PRINTER_HANDLE::default();
    // SAFETY: opening the local print server (null name) for change
    // monitoring; `&raw mut printer` receives the handle.
    let opened = unsafe { OpenPrinterW(PCWSTR::null(), &raw mut printer, None) };
    if opened.is_err() {
        tracing::info!(target: "sng_pal::dlp", "OpenPrinterW failed; print channel idle");
        return;
    }
    // SAFETY: arm the add-job notification on the opened server handle;
    // `FindFirstPrinterChangeNotification` returns the change handle
    // directly (an invalid handle signals failure).
    let change = unsafe {
        FindFirstPrinterChangeNotification(printer, PRINTER_CHANGE_ADD_JOB, 0, None)
    };
    if change.is_invalid() {
        // SAFETY: `printer` is a valid handle opened above.
        unsafe { let _ = ClosePrinter(printer); };
        return;
    }
    while !shared.is_closed() {
        // SAFETY: wait up to 1s on the change object so the loop can
        // observe the shutdown flag.
        let wait = unsafe { WaitForSingleObject(change, 1000) };
        if wait == WAIT_OBJECT_0 {
            let mut flags = 0u32;
            // SAFETY: drain the change so the next job re-signals.
            let _ = unsafe {
                FindNextPrinterChangeNotification(change, Some(&raw mut flags), None, None)
            };
            shared.push(ContentEvent {
                channel: DlpChannel::Print,
                content: Vec::new(),
                metadata: ContentMetadata {
                    filename: None,
                    content_type: None,
                    source: Some("print-spooler".to_owned()),
                    mip_labels: Vec::new(),
                    ..ContentMetadata::default()
                },
            });
        }
    }
    // SAFETY: both handles were opened above and are released once.
    unsafe {
        let _ = FindClosePrinterChangeNotification(change);
        let _ = ClosePrinter(printer);
    }
}

// ---------------------------------------------------------------------------
// Clipboard — format-listener chain on a message-only window
// ---------------------------------------------------------------------------

/// Windows clipboard monitor — joins the format-listener chain and
/// reports `CF_UNICODETEXT` selections when they change.
#[derive(Debug)]
pub struct WindowsClipboardMonitor {
    shared: Arc<ChannelBuffer>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Message-only window handle as `isize` for `Send`; used to post a
    /// quit message on shutdown.
    hwnd: Mutex<isize>,
    fallback_closed: Arc<AtomicBool>,
    native: bool,
}

impl Default for WindowsClipboardMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsClipboardMonitor {
    /// A new, open clipboard monitor. Spawns the listener-window worker;
    /// if window creation fails the monitor falls back to PowerShell
    /// `Get-Clipboard` on demand.
    #[must_use]
    pub fn new() -> Self {
        let shared = ChannelBuffer::new();
        let (tx, rx) = std::sync::mpsc::channel::<isize>();
        let shared_w = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("sng-dlp-clipboard".to_owned())
            .spawn(move || clipboard_worker(&shared_w, &tx))
            .ok();
        // The worker reports its HWND (or 0 on failure) once the window
        // is created, so `new` knows whether the native path is live.
        let hwnd = worker
            .as_ref()
            .and_then(|_| rx.recv_timeout(Duration::from_secs(2)).ok())
            .unwrap_or(0);
        let native = worker.is_some() && hwnd != 0;
        Self {
            shared,
            worker: Mutex::new(worker),
            hwnd: Mutex::new(hwnd),
            fallback_closed: Arc::new(AtomicBool::new(false)),
            native,
        }
    }

    /// Tear the monitor down; a subsequent `next_event` returns `Ok(None)`.
    pub fn shutdown(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.fallback_closed.store(true, Ordering::SeqCst);
        let hwnd = *lock(&self.hwnd);
        if hwnd != 0 {
            use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};
            // SAFETY: posting WM_CLOSE to our own message window unblocks
            // its loop; a null/!invalid handle is tolerated by the API.
            unsafe {
                let _ = PostMessageW(
                    Some(HWND(hwnd as *mut std::ffi::c_void)),
                    WM_CLOSE,
                    WPARAM(0),
                    LPARAM(0),
                );
            }
        }
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
    }
}

impl Drop for WindowsClipboardMonitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[async_trait]
impl ChannelInterceptor for WindowsClipboardMonitor {
    fn channel(&self) -> DlpChannel {
        DlpChannel::Clipboard
    }
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        if self.native {
            loop {
                if let Some(e) = self.shared.pop() {
                    return Ok(Some(e));
                }
                if self.shared.is_closed() {
                    return Ok(None);
                }
                tokio::time::sleep(DRAIN_TICK).await;
            }
        } else {
            // PowerShell fallback: read on demand, dedup by hash.
            loop {
                if self.fallback_closed.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                if let Some(bytes) = read_get_clipboard() {
                    return Ok(Some(ContentEvent {
                        channel: DlpChannel::Clipboard,
                        content: bytes,
                        metadata: clipboard_metadata(),
                    }));
                }
                tokio::time::sleep(Duration::from_millis(700)).await;
            }
        }
    }
}

/// Per-window state pointed to by `GWLP_USERDATA`.
struct ClipboardWindowState {
    shared: Arc<ChannelBuffer>,
    last_hash: Option<u64>,
}

/// Message-only clipboard listener worker. Creates the window, joins
/// the format-listener chain, and pumps messages until WM_CLOSE.
fn clipboard_worker(shared: &Arc<ChannelBuffer>, tx: &std::sync::mpsc::Sender<isize>) {
    use windows::Win32::System::DataExchange::{
        AddClipboardFormatListener, RemoveClipboardFormatListener,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, DispatchMessageW, GWLP_USERDATA, GetMessageW, HWND_MESSAGE,
        MSG, RegisterClassW, SetWindowLongPtrW, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
    };

    use windows::Win32::Foundation::HINSTANCE;
    // SAFETY: module handle for the current process; used as hInstance.
    let Ok(hmodule) = (unsafe { GetModuleHandleW(PCWSTR::null()) }) else {
        let _ = tx.send(0);
        return;
    };
    let hinstance = HINSTANCE(hmodule.0);
    let class_name = w!("SngDlpClipboardListener");
    let wc = WNDCLASSW {
        lpfnWndProc: Some(clipboard_wndproc),
        hInstance: hinstance,
        lpszClassName: class_name,
        ..Default::default()
    };
    // SAFETY: registering a window class with a static name; a zero
    // atom (already-registered) is also acceptable for CreateWindowExW.
    let _atom = unsafe { RegisterClassW(&raw const wc) };

    // SAFETY: create a message-only window (HWND_MESSAGE parent).
    let hwnd = match unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("sng-dlp"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(hinstance),
            None,
        )
    } {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            let _ = tx.send(0);
            return;
        }
    };

    // Install per-window state and join the listener chain.
    let state = Box::into_raw(Box::new(ClipboardWindowState {
        shared: Arc::clone(shared),
        last_hash: None,
    }));
    // SAFETY: stash the state pointer in the window's user data so the
    // wndproc can reach it; reclaimed below after the loop.
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
        let _ = AddClipboardFormatListener(hwnd);
    }
    let _ = tx.send(hwnd.0 as isize);

    let mut msg = MSG::default();
    loop {
        // SAFETY: standard blocking message pump; returns FALSE on
        // WM_QUIT, <0 on error.
        let got = unsafe { GetMessageW(&raw mut msg, Some(hwnd), 0, 0) };
        if got.0 <= 0 {
            break;
        }
        // SAFETY: dispatch routes to `clipboard_wndproc`.
        unsafe {
            let _ = DispatchMessageW(&raw const msg);
        }
        if shared.is_closed() {
            break;
        }
    }

    // SAFETY: leave the chain, destroy the window, reclaim the state.
    unsafe {
        let _ = RemoveClipboardFormatListener(hwnd);
        let _ = DestroyWindow(hwnd);
        drop(Box::from_raw(state));
    }
}

/// Window procedure: on `WM_CLIPBOARDUPDATE` read the UTF-16 selection
/// and queue it (deduped) as a content event.
extern "system" fn clipboard_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::{
        DefWindowProcW, GWLP_USERDATA, GetWindowLongPtrW, WM_CLIPBOARDUPDATE,
    };
    if msg == WM_CLIPBOARDUPDATE {
        // SAFETY: retrieve the state pointer stored in `new`.
        let ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut ClipboardWindowState;
        if !ptr.is_null() {
            // SAFETY: `ptr` is the live Box installed for this window;
            // single-threaded access on the window's own thread.
            let state = unsafe { &mut *ptr };
            if let Some(bytes) = read_clipboard_unicode(hwnd) {
                let hash = content_hash(&bytes);
                if state.last_hash != Some(hash) && !bytes.is_empty() {
                    state.last_hash = Some(hash);
                    state.shared.push(ContentEvent {
                        channel: DlpChannel::Clipboard,
                        content: bytes,
                        metadata: clipboard_metadata(),
                    });
                }
            }
        }
        return LRESULT(0);
    }
    // SAFETY: default handling for everything else.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Read `CF_UNICODETEXT` from the clipboard as UTF-8 bytes.
fn read_clipboard_unicode(hwnd: HWND) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::HANDLE as FHANDLE;
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    // SAFETY: open the clipboard associated with our window.
    unsafe { OpenClipboard(Some(hwnd)).ok()? };
    let result = (|| {
        // SAFETY: fetch the unicode-text handle (borrowed, not freed).
        let h = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT.0)) }.ok()?;
        let hglobal = HGLOBAL(h.0);
        // SAFETY: lock the global memory to read the wide string.
        let ptr = unsafe { GlobalLock(hglobal) } as *const u16;
        if ptr.is_null() {
            return None;
        }
        // Determine length up to the NUL terminator.
        let mut len = 0usize;
        // SAFETY: the buffer is a NUL-terminated wide string.
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
        }
        // SAFETY: `len` units precede the terminator.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        let text = String::from_utf16_lossy(slice);
        // SAFETY: balance the lock.
        unsafe { let _ = GlobalUnlock(hglobal); };
        let _ = FHANDLE::default;
        Some(text.into_bytes())
    })();
    // SAFETY: always close the clipboard we opened.
    unsafe { let _ = CloseClipboard(); };
    result
}

/// PowerShell `Get-Clipboard` fallback.
fn read_get_clipboard() -> Option<Vec<u8>> {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-Clipboard -Raw"])
        .output()
        .ok()?;
    if output.status.success() && !output.stdout.is_empty() {
        Some(output.stdout)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// WFP egress guard (enforcement helper)
// ---------------------------------------------------------------------------

/// A handle to the Windows Filtering Platform engine plus a dedicated
/// sublayer, used by the agent to block network egress on a DLP
/// `Block` verdict. Closing the guard removes the sublayer and the
/// engine session.
#[derive(Debug)]
pub struct WindowsWfpEgressGuard {
    engine: isize,
    sublayer: windows::core::GUID,
}

impl WindowsWfpEgressGuard {
    /// Open a dynamic WFP engine session and register the egress
    /// sublayer. `Err` carries the Win32 error when WFP is unavailable
    /// (e.g. the Base Filtering Engine service is stopped).
    pub fn open() -> Result<Self, String> {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWPM_SESSION0, FWPM_SUBLAYER0, FwpmEngineOpen0, FwpmSubLayerAdd0,
        };
        use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine = HANDLE::default();
        // Dynamic session: the sublayer/filters are removed automatically
        // when the engine handle closes, so a crashed agent never leaves
        // stale egress blocks behind ("no ops").
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        // SAFETY: documented WFP engine open; `&raw mut engine` receives
        // the session handle. A non-zero return is mapped to Err.
        let rc = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&raw const session),
                &raw mut engine,
            )
        };
        if rc != 0 {
            return Err(format!("FwpmEngineOpen0 failed: {rc:#x}"));
        }

        // Stable, well-known sublayer key for the agent's egress layer so
        // it is recognisable across restarts (the dynamic session still
        // tears it down on handle close).
        let sublayer_key = windows::core::GUID::from_u128(0x9f2b_1c34_5d6e_47a8_b9c0_1234_5678_90ab);
        let name: Vec<u16> = "SNG DLP egress\0".encode_utf16().collect();
        let mut sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_key,
            ..Default::default()
        };
        sublayer.displayData.name = windows::core::PWSTR(name.as_ptr().cast_mut());
        sublayer.weight = 0x0100;
        // SAFETY: add the sublayer to the engine opened above; `name`
        // outlives the call.
        let rc = unsafe { FwpmSubLayerAdd0(HANDLE(engine.0), &raw const sublayer, None) };
        if rc != 0 {
            // SAFETY: close the engine we just opened before erroring.
            unsafe {
                let _ = windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(engine);
            }
            return Err(format!("FwpmSubLayerAdd0 failed: {rc:#x}"));
        }

        Ok(Self {
            engine: engine.0 as isize,
            sublayer: sublayer_key,
        })
    }

    /// The GUID of the registered egress sublayer (filters added by the
    /// agent reference it).
    #[must_use]
    pub fn sublayer(&self) -> windows::core::GUID {
        self.sublayer
    }
}

impl Drop for WindowsWfpEgressGuard {
    fn drop(&mut self) {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
        // SAFETY: `engine` was opened in `open`; closing a dynamic
        // session removes the sublayer automatically.
        unsafe {
            let _ = FwpmEngineClose0(HANDLE(self.engine as *mut std::ffi::c_void));
        }
    }
}
