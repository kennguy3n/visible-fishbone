// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Commodity-hardware optimisation for the edge appliance.
//!
//! ShieldNet's edge is a *software* appliance designed to run on cheap,
//! ubiquitous branch hardware — a 2-core ARM or x86 box with 2 GB of
//! RAM and an 8 GB storage micro-branch is the documented floor (see
//! [`COMMODITY_BASELINE`] and `docs/commodity-hardware.md`). This module
//! gives the edge the three levers that let it forward traffic
//! efficiently on hardware that small:
//!
//! 1. **Host topology probe** ([`HostTopology`]) — logical CPUs, NUMA
//!    node layout, total RAM, and free storage on the data directory.
//!    On Linux it reads `/sys` / `/proc` / `statvfs`; elsewhere it
//!    degrades to the portable [`std::thread::available_parallelism`]
//!    plus best-effort defaults so the type is usable cross-platform
//!    (and in tests).
//! 2. **Minimum-spec preflight** ([`MinSpec`] / [`SpecAssessment`]) —
//!    compares the probed topology against the commodity baseline and
//!    reports `Pass` / `Warn` / `Fail` with human-readable reasons, so
//!    the operator finds out at boot that a box is undersized rather
//!    than when it falls over under load.
//! 3. **CPU-affinity plan** ([`AffinityPlan`]) — a NUMA-aware mapping of
//!    forwarding-worker threads onto logical CPUs that keeps each
//!    worker's CPUs on a single NUMA node (so a worker never pays the
//!    cross-node memory penalty). The plan is pure and testable;
//!    [`AffinityPlan::pin_current_thread`] applies it via
//!    `sched_setaffinity` on Linux and is a documented no-op elsewhere.
//! 4. **Zero-copy packet-buffer pool** ([`MmapBufferPool`]) — a fixed
//!    set of equal-size frames carved out of one anonymous
//!    memory-mapped region. The data path forwards by passing frame
//!    handles (indices into the map), never by copying packet bytes,
//!    which is what keeps per-packet cost flat on a small box.
//!
//! # Relationship to the eBPF/XDP fast path
//!
//! The optional XDP fast path is owned by Stream 2D; this module does
//! not implement it. It only *consumes* the resolved data-path
//! selection ([`DataPathProfile::from_selection`]) so the buffer pool
//! can be sized appropriately and the boot summary can report whether
//! the fast path is active. When XDP lands, its frames can be backed by
//! the same [`MmapBufferPool`] region (an XDP UMEM is exactly a shared
//! mmap of fixed frames), so the seam is deliberately compatible.

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::cli::DataPathSelection;

/// One gibibyte in bytes — the unit the commodity baseline is quoted in.
pub const GIB: u64 = 1024 * 1024 * 1024;

/// The documented commodity-hardware floor: a 2-core CPU, 2 GiB of RAM,
/// and an 8 GiB storage micro-branch. A host at or above every bound
/// passes the preflight; below any bound it fails.
pub const COMMODITY_BASELINE: MinSpec = MinSpec {
    min_logical_cpus: 2,
    min_memory_bytes: 2 * GIB,
    min_storage_bytes: 8 * GIB,
};

// ---------------------------------------------------------------------
// Host topology
// ---------------------------------------------------------------------

/// A single NUMA node and the logical CPUs local to it.
///
/// On a non-NUMA box (the common commodity case) the topology has
/// exactly one node owning every CPU, so affinity planning still works
/// without special-casing the uniform-memory machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumaNode {
    /// Kernel NUMA node id (0-based; `0` on a uniform-memory host).
    pub id: usize,
    /// Logical CPU ids local to this node, ascending.
    pub cpus: Vec<usize>,
}

/// A snapshot of the host's compute and storage shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostTopology {
    /// Total online logical CPUs (hyperthreads count individually).
    pub logical_cpus: usize,
    /// NUMA nodes, ascending by id. Always non-empty: a uniform-memory
    /// host is reported as a single node owning every CPU.
    pub numa_nodes: Vec<NumaNode>,
    /// Total physical RAM in bytes (`0` if it could not be probed).
    pub total_memory_bytes: u64,
    /// Bytes available to the edge on its data directory's filesystem
    /// (`0` if it could not be probed).
    pub data_dir_available_bytes: u64,
}

impl HostTopology {
    /// Probe the running host. `data_dir` is the path whose filesystem
    /// free space is measured (the edge's spool / bundle cache dir).
    ///
    /// Detection is best-effort and never fails: any field that cannot
    /// be read falls back to a safe default (`available_parallelism`
    /// for CPUs, a single NUMA node, `0` for an unreadable
    /// memory/storage figure) so callers always get a usable topology.
    #[must_use]
    pub fn detect(data_dir: &Path) -> Self {
        let logical_cpus = detect_logical_cpus();
        let numa_nodes = detect_numa_nodes(logical_cpus);
        Self {
            logical_cpus,
            numa_nodes,
            total_memory_bytes: detect_total_memory_bytes(),
            data_dir_available_bytes: detect_available_storage_bytes(data_dir),
        }
    }

    /// Number of NUMA nodes (>= 1).
    #[must_use]
    pub fn numa_node_count(&self) -> usize {
        self.numa_nodes.len()
    }
}

fn detect_logical_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Build the NUMA node list. On Linux this parses
/// `/sys/devices/system/node/node*/cpulist`; on any other platform, or
/// when `/sys` is unavailable (containers frequently mask it), it
/// returns a single node owning CPUs `0..logical_cpus`.
fn detect_numa_nodes(logical_cpus: usize) -> Vec<NumaNode> {
    #[cfg(target_os = "linux")]
    {
        if let Some(nodes) = read_linux_numa_nodes() {
            if !nodes.is_empty() {
                return nodes;
            }
        }
    }
    vec![uniform_node(logical_cpus)]
}

/// The fallback single node owning every CPU `0..logical_cpus`.
fn uniform_node(logical_cpus: usize) -> NumaNode {
    NumaNode {
        id: 0,
        cpus: (0..logical_cpus.max(1)).collect(),
    }
}

#[cfg(target_os = "linux")]
fn read_linux_numa_nodes() -> Option<Vec<NumaNode>> {
    let base = Path::new("/sys/devices/system/node");
    let mut nodes = Vec::new();
    // Per-node errors are skipped, not propagated: one unreadable
    // node directory or cpulist must not discard the whole topology
    // and collapse the host to the single-uniform-node fallback. A
    // partial-but-real NUMA map (the nodes we could read) still pins
    // workers correctly — AffinityPlan only ever indexes the nodes
    // present in this list — whereas the uniform fallback loses all
    // locality. Only a completely unreadable /sys/.../node directory
    // (read_dir failing) returns None for the uniform fallback.
    for entry in std::fs::read_dir(base).ok()? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(id_str) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(id) = id_str.parse::<usize>() else {
            continue;
        };
        let Ok(cpulist) = std::fs::read_to_string(entry.path().join("cpulist")) else {
            continue;
        };
        let cpus = parse_cpulist(&cpulist);
        if !cpus.is_empty() {
            nodes.push(NumaNode { id, cpus });
        }
    }
    nodes.sort_by_key(|n| n.id);
    Some(nodes)
}

/// Parse a Linux `cpulist` string (e.g. `"0-3,8,10-11"`) into an
/// ascending list of CPU ids. Malformed ranges are skipped rather than
/// erroring — a partial list is more useful than none for planning.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_cpulist(s: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in s.trim().split(',') {
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<usize>(), hi.trim().parse::<usize>()) {
                for c in lo..=hi {
                    cpus.push(c);
                }
            }
        } else if let Ok(c) = part.trim().parse::<usize>() {
            cpus.push(c);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

fn detect_total_memory_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            return parse_meminfo_total_bytes(&meminfo);
        }
    }
    0
}

/// Parse `MemTotal:    N kB` out of `/proc/meminfo` into bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_meminfo_total_bytes(meminfo: &str) -> u64 {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Format: "MemTotal:       16317840 kB".
            let mut it = rest.split_whitespace();
            if let Some(kb) = it.next().and_then(|v| v.parse::<u64>().ok()) {
                return kb.saturating_mul(1024);
            }
        }
    }
    0
}

#[cfg(unix)]
fn detect_available_storage_bytes(data_dir: &Path) -> u64 {
    // statvfs reports the free space available to an unprivileged
    // process (f_bavail), which is the figure that matters for the
    // edge's spool. A path that does not exist yet (first boot before
    // the dir is created) is walked up to its nearest existing parent.
    let mut probe = data_dir;
    loop {
        match nix::sys::statvfs::statvfs(probe) {
            Ok(st) => {
                // statvfs field widths differ by platform: fsblkcnt_t is
                // u32 on macOS but u64 on Linux, and fragment_size is
                // c_ulong. Cast both to u64 so the multiply is well-typed
                // everywhere (the cast is a no-op on Linux, hence the
                // targeted allow so `-D warnings` stays clean there).
                #[allow(clippy::unnecessary_cast)]
                let bavail = st.blocks_available() as u64;
                #[allow(clippy::unnecessary_cast)]
                let frsize = st.fragment_size() as u64;
                return bavail.saturating_mul(frsize);
            }
            Err(_) => match probe.parent() {
                Some(parent) => probe = parent,
                None => return 0,
            },
        }
    }
}

#[cfg(not(unix))]
fn detect_available_storage_bytes(_data_dir: &Path) -> u64 {
    0
}

// ---------------------------------------------------------------------
// Minimum-spec preflight
// ---------------------------------------------------------------------

/// The minimum host shape the edge is supported on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinSpec {
    /// Minimum online logical CPUs.
    pub min_logical_cpus: usize,
    /// Minimum total RAM in bytes.
    pub min_memory_bytes: u64,
    /// Minimum free storage on the data directory in bytes.
    pub min_storage_bytes: u64,
}

/// The outcome of comparing a [`HostTopology`] against a [`MinSpec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecAssessment {
    /// Every bound is satisfied.
    Pass,
    /// Every *hard* bound (CPU, RAM) is satisfied but a soft bound
    /// (storage, or a probe that returned `0`/unknown) could not be
    /// confirmed. The edge boots; the reasons explain what to check.
    Warn(Vec<String>),
    /// At least one hard bound (CPU or RAM) is below the floor. The
    /// reasons name every failing bound.
    Fail(Vec<String>),
}

impl SpecAssessment {
    /// True for [`Self::Pass`].
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// True for [`Self::Fail`] — the host is below a hard minimum.
    #[must_use]
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail(_))
    }
}

impl MinSpec {
    /// Assess `topology` against this spec.
    ///
    /// CPU and RAM are *hard* bounds: falling short of either yields
    /// [`SpecAssessment::Fail`]. Storage is a *soft* bound (a small
    /// spool can be expanded, and the figure is unavailable on
    /// non-unix / masked filesystems), so a storage shortfall — or any
    /// metric that probed as unknown (`0`) — yields
    /// [`SpecAssessment::Warn`] rather than blocking boot.
    #[must_use]
    pub fn assess(&self, topology: &HostTopology) -> SpecAssessment {
        let mut fails = Vec::new();
        let mut warns = Vec::new();

        if topology.logical_cpus < self.min_logical_cpus {
            fails.push(format!(
                "cpu: {} logical core(s) < {} minimum",
                topology.logical_cpus, self.min_logical_cpus
            ));
        }

        if topology.total_memory_bytes == 0 {
            warns.push("memory: total RAM could not be probed (no /proc/meminfo)".to_owned());
        } else if topology.total_memory_bytes < self.min_memory_bytes {
            fails.push(format!(
                "memory: {} < {} minimum",
                human_bytes(topology.total_memory_bytes),
                human_bytes(self.min_memory_bytes)
            ));
        }

        if topology.data_dir_available_bytes == 0 {
            warns.push("storage: free space could not be probed".to_owned());
        } else if topology.data_dir_available_bytes < self.min_storage_bytes {
            warns.push(format!(
                "storage: {} free < {} minimum",
                human_bytes(topology.data_dir_available_bytes),
                human_bytes(self.min_storage_bytes)
            ));
        }

        if !fails.is_empty() {
            // Surface soft warnings alongside the hard failures so a
            // single boot log line is complete.
            fails.extend(warns);
            SpecAssessment::Fail(fails)
        } else if warns.is_empty() {
            SpecAssessment::Pass
        } else {
            SpecAssessment::Warn(warns)
        }
    }
}

/// Render a byte count as a compact human string (`2.0 GiB`).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    #[allow(clippy::cast_precision_loss)]
    let b = bytes as f64;
    let mut val = b;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{val:.1} {}", UNITS[unit])
    }
}

// ---------------------------------------------------------------------
// CPU-affinity plan
// ---------------------------------------------------------------------

/// The CPU affinity assigned to one forwarding-worker thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerAffinity {
    /// 0-based worker index in the plan.
    pub worker: usize,
    /// NUMA node this worker is confined to.
    pub numa_node: usize,
    /// Logical CPUs the worker may run on (all on `numa_node`).
    pub cpus: Vec<usize>,
}

/// A NUMA-aware assignment of worker threads onto logical CPUs.
///
/// Workers are spread across NUMA nodes round-robin and, within a node,
/// across that node's CPUs, so each worker's CPU set stays on one node
/// (no cross-node memory traffic) while every CPU is used before any is
/// doubled up. The plan is a pure value; nothing is applied to the OS
/// until [`Self::pin_current_thread`] is called from the worker thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffinityPlan {
    assignments: Vec<WorkerAffinity>,
}

impl AffinityPlan {
    /// Compute a plan placing `workers` threads across `topology`.
    ///
    /// `workers` is clamped to a floor of 1. Each worker is pinned to a
    /// single CPU when there are at least as many CPUs as workers on
    /// the chosen node; once workers outnumber a node's CPUs they share
    /// CPUs round-robin (the kernel scheduler then time-slices them).
    #[must_use]
    pub fn compute(topology: &HostTopology, workers: usize) -> Self {
        let workers = workers.max(1);
        let nodes = &topology.numa_nodes;
        // Per-node rotating cursor so successive workers landing on the
        // same node take successive CPUs.
        let mut node_cursor = vec![0usize; nodes.len().max(1)];
        let mut assignments = Vec::with_capacity(workers);

        for w in 0..workers {
            if nodes.is_empty() {
                assignments.push(WorkerAffinity {
                    worker: w,
                    numa_node: 0,
                    cpus: Vec::new(),
                });
                continue;
            }
            let node_idx = w % nodes.len();
            let node = &nodes[node_idx];
            let cpus = if node.cpus.is_empty() {
                Vec::new()
            } else {
                let cursor = node_cursor[node_idx];
                node_cursor[node_idx] = cursor.wrapping_add(1);
                vec![node.cpus[cursor % node.cpus.len()]]
            };
            assignments.push(WorkerAffinity {
                worker: w,
                numa_node: node.id,
                cpus,
            });
        }
        Self { assignments }
    }

    /// The per-worker assignments, ascending by worker index.
    #[must_use]
    pub fn assignments(&self) -> &[WorkerAffinity] {
        &self.assignments
    }

    /// Pin the *calling* thread to the CPU set assigned to `worker`.
    ///
    /// On Linux this issues `sched_setaffinity(0, …)`. On every other
    /// platform it is a no-op returning [`AffinityError::Unsupported`]
    /// so callers can log the degraded state without `cfg` at the call
    /// site. Returns [`AffinityError::UnknownWorker`] if `worker` is
    /// out of range or [`AffinityError::EmptyCpuSet`] if the assignment
    /// carries no CPUs (a topology probe that found none).
    ///
    /// # Errors
    ///
    /// See the variants of [`AffinityError`].
    pub fn pin_current_thread(&self, worker: usize) -> Result<(), AffinityError> {
        let assignment = self
            .assignments
            .get(worker)
            .ok_or(AffinityError::UnknownWorker(worker))?;
        if assignment.cpus.is_empty() {
            return Err(AffinityError::EmptyCpuSet(worker));
        }
        pin_thread_to_cpus(&assignment.cpus)
    }
}

/// Why pinning a thread's CPU affinity failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffinityError {
    /// The worker index has no assignment in the plan.
    UnknownWorker(usize),
    /// The worker's assignment carries no CPUs to pin to.
    EmptyCpuSet(usize),
    /// CPU pinning is not implemented on this platform (non-Linux).
    Unsupported,
    /// The `sched_setaffinity` syscall failed.
    Syscall(String),
}

impl fmt::Display for AffinityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownWorker(w) => write!(f, "no affinity assignment for worker {w}"),
            Self::EmptyCpuSet(w) => write!(f, "worker {w} has an empty CPU set"),
            Self::Unsupported => write!(f, "CPU affinity pinning is unsupported on this platform"),
            Self::Syscall(e) => write!(f, "sched_setaffinity failed: {e}"),
        }
    }
}

impl std::error::Error for AffinityError {}

#[cfg(target_os = "linux")]
fn pin_thread_to_cpus(cpus: &[usize]) -> Result<(), AffinityError> {
    use nix::sched::{CpuSet, sched_setaffinity};
    use nix::unistd::Pid;

    let mut set = CpuSet::new();
    for &cpu in cpus {
        set.set(cpu)
            .map_err(|e| AffinityError::Syscall(e.to_string()))?;
    }
    // Pid 0 == the calling thread.
    sched_setaffinity(Pid::from_raw(0), &set).map_err(|e| AffinityError::Syscall(e.to_string()))
}

#[cfg(not(target_os = "linux"))]
fn pin_thread_to_cpus(_cpus: &[usize]) -> Result<(), AffinityError> {
    Err(AffinityError::Unsupported)
}

// ---------------------------------------------------------------------
// Zero-copy memory-mapped buffer pool
// ---------------------------------------------------------------------

/// A fixed-capacity pool of equal-size packet frames carved out of one
/// anonymous memory-mapped region.
///
/// The whole region is mapped once at construction; [`acquire`] hands
/// out a [`Frame`] that borrows a non-overlapping slice of it, and the
/// frame returns its slot to the pool on drop. Forwarding therefore
/// moves *frame handles* (a small index), never packet bytes — the
/// zero-copy property the commodity edge depends on. The same region
/// shape (N fixed frames) is what an XDP UMEM expects, so a future
/// fast-path can adopt this pool unchanged.
///
/// [`acquire`]: MmapBufferPool::acquire
#[derive(Clone)]
pub struct MmapBufferPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    // The backing map is kept alive for the pool's lifetime; frames
    // index into it via `base`. It is never accessed through this field
    // directly (all access goes through the raw base pointer), so the
    // field only exists to own the mapping.
    _map: memmap2::MmapMut,
    base: *mut u8,
    frame_bytes: usize,
    frame_count: usize,
    free: Mutex<Vec<usize>>,
}

// SAFETY: `PoolInner` holds a raw `*mut u8` into the owned mmap, which
// makes it neither `Send` nor `Sync` automatically. It is sound to send
// and share across threads because: (a) the mapping is owned by the
// `Arc<PoolInner>` and outlives every `Frame`; (b) frame slots are
// handed out through a `Mutex`-guarded free list, so no two live frames
// ever address the same slot; and (c) each `Frame` only ever touches
// its own non-overlapping `[base + i*frame_bytes, +frame_bytes)` range.
// The free list's `Mutex` provides the synchronisation for slot
// ownership transfer.
#[allow(unsafe_code)]
unsafe impl Send for PoolInner {}
#[allow(unsafe_code)]
unsafe impl Sync for PoolInner {}

/// Why constructing an [`MmapBufferPool`] failed.
#[derive(Debug)]
pub enum BufferPoolError {
    /// `frame_bytes` or `frame_count` was zero.
    ZeroSized,
    /// The anonymous memory map could not be created.
    Map(std::io::Error),
}

impl fmt::Display for BufferPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSized => write!(f, "frame_bytes and frame_count must both be non-zero"),
            Self::Map(e) => write!(f, "anonymous mmap failed: {e}"),
        }
    }
}

impl std::error::Error for BufferPoolError {}

impl MmapBufferPool {
    /// Map a pool of `frame_count` frames of `frame_bytes` each.
    ///
    /// # Errors
    ///
    /// [`BufferPoolError::ZeroSized`] if either dimension is zero;
    /// [`BufferPoolError::Map`] if the OS refuses the anonymous map.
    pub fn new(frame_bytes: usize, frame_count: usize) -> Result<Self, BufferPoolError> {
        if frame_bytes == 0 || frame_count == 0 {
            return Err(BufferPoolError::ZeroSized);
        }
        let len = frame_bytes
            .checked_mul(frame_count)
            .ok_or(BufferPoolError::ZeroSized)?;
        let mut map = memmap2::MmapOptions::new()
            .len(len)
            .map_anon()
            .map_err(BufferPoolError::Map)?;
        let base = map.as_mut_ptr();
        let free: Vec<usize> = (0..frame_count).rev().collect();
        Ok(Self {
            inner: Arc::new(PoolInner {
                _map: map,
                base,
                frame_bytes,
                frame_count,
                free: Mutex::new(free),
            }),
        })
    }

    /// Total frames in the pool.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.frame_count
    }

    /// Size of each frame in bytes.
    #[must_use]
    pub fn frame_size(&self) -> usize {
        self.inner.frame_bytes
    }

    /// Frames currently checked out (not in the free list).
    ///
    /// # Panics
    ///
    /// Panics only if the internal free-list mutex was poisoned by a
    /// thread that panicked while holding it — which cannot happen on
    /// the lock's short, panic-free critical sections.
    #[must_use]
    pub fn frames_in_use(&self) -> usize {
        // Recover from a poisoned lock rather than panicking: the
        // free-list invariant survives a poisoning panic because every
        // critical section is a panic-free Vec push/pop.
        let free = self
            .inner
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.inner.frame_count - free.len()
    }

    /// Check out a free frame, or `None` if the pool is exhausted.
    ///
    /// The returned [`Frame`] holds the slot until dropped.
    #[must_use]
    pub fn acquire(&self) -> Option<Frame> {
        let idx = {
            let mut free = self
                .inner
                .free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            free.pop()?
        };
        Some(Frame {
            pool: Arc::clone(&self.inner),
            index: idx,
        })
    }
}

impl fmt::Debug for MmapBufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapBufferPool")
            .field("frame_bytes", &self.inner.frame_bytes)
            .field("frame_count", &self.inner.frame_count)
            .field("frames_in_use", &self.frames_in_use())
            .finish()
    }
}

/// An exclusive handle to one frame of an [`MmapBufferPool`].
///
/// Derefs to the frame's `[u8]` backing bytes. Returns its slot to the
/// pool when dropped.
///
/// # Safety invariant
///
/// `Frame` must **never** derive or implement `Clone`/`Copy`. The unsafe
/// pointer arithmetic in [`Frame::as_slice`] / [`Frame::as_mut_slice`] is
/// sound only because each live `Frame` exclusively owns its slot
/// `index` (popped from the pool's free list, returned on drop). A
/// second `Frame` referencing the same slot would alias the same
/// `&mut [u8]`, which is undefined behaviour. Exclusive `&mut self` on
/// `as_mut_slice` and the one-handle-per-slot invariant together provide
/// the aliasing guarantee; cloning would break it. To get a second
/// frame, [`MmapBufferPool::acquire`] a distinct slot.
pub struct Frame {
    pool: Arc<PoolInner>,
    index: usize,
}

impl Frame {
    /// The frame's index within the pool (its stable slot id).
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Immutable view of the frame bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `index` is this frame's exclusively-owned slot (it was
        // popped from the free list and is not returned until drop), so
        // the `[off, off+frame_bytes)` range is non-overlapping with
        // every other live frame and stays inside the mapped region
        // (`off + frame_bytes <= frame_bytes * frame_count == map len`).
        #[allow(unsafe_code)]
        unsafe {
            let off = self.index * self.pool.frame_bytes;
            std::slice::from_raw_parts(self.pool.base.add(off), self.pool.frame_bytes)
        }
    }

    /// Mutable view of the frame bytes.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as for `as_slice`, plus `&mut self` guarantees no
        // other reference to this frame's bytes exists, so handing out a
        // `&mut [u8]` to the slot is exclusive.
        #[allow(unsafe_code)]
        unsafe {
            let off = self.index * self.pool.frame_bytes;
            std::slice::from_raw_parts_mut(self.pool.base.add(off), self.pool.frame_bytes)
        }
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        // Always return the slot, even through a poisoned lock, so an
        // unrelated panic elsewhere cannot leak frames out of the pool.
        let mut free = self
            .pool
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        free.push(self.index);
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("index", &self.index)
            .field("frame_bytes", &self.pool.frame_bytes)
            .finish()
    }
}

// ---------------------------------------------------------------------
// Data-path profile (eBPF feature-flag consumption)
// ---------------------------------------------------------------------

/// How the edge's data path is configured, derived from the resolved
/// [`DataPathSelection`]. This module does not implement the XDP fast
/// path (Stream 2D owns it); it only records whether the fast path is
/// active so the buffer pool can be sized and the boot summary can
/// report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataPathProfile {
    /// The resolved backend (`Auto` is never seen here — it has already
    /// been resolved to `Ebpf` or `Nftables`).
    pub backend: DataPathSelection,
    /// True iff the eBPF/XDP fast path is the active backend.
    pub xdp_fast_path: bool,
}

impl DataPathProfile {
    /// Default frames in the buffer pool when the slow path is active.
    pub const SLOW_PATH_FRAMES: usize = 1024;
    /// Frames when the XDP fast path is active — a larger UMEM keeps
    /// the NIC ring fed without head-of-line blocking.
    pub const FAST_PATH_FRAMES: usize = 4096;
    /// Frame size: one standard 1500-byte MTU packet rounded up to a
    /// 2 KiB power-of-two slot (the conventional XDP frame size).
    pub const FRAME_BYTES: usize = 2048;

    /// Derive the profile from a resolved data-path selection.
    #[must_use]
    pub fn from_selection(backend: DataPathSelection) -> Self {
        Self {
            backend,
            xdp_fast_path: matches!(backend, DataPathSelection::Ebpf),
        }
    }

    /// Recommended frame count for the buffer pool given the backend.
    #[must_use]
    pub fn recommended_frame_count(&self) -> usize {
        if self.xdp_fast_path {
            Self::FAST_PATH_FRAMES
        } else {
            Self::SLOW_PATH_FRAMES
        }
    }

    /// Allocate a buffer pool sized for this data-path profile.
    ///
    /// # Errors
    ///
    /// Propagates [`BufferPoolError`] from [`MmapBufferPool::new`].
    pub fn allocate_pool(&self) -> Result<MmapBufferPool, BufferPoolError> {
        MmapBufferPool::new(Self::FRAME_BYTES, self.recommended_frame_count())
    }
}

// ---------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------

/// The complete commodity-hardware profile assembled at edge boot: the
/// probed topology, the min-spec assessment, the worker affinity plan,
/// and the data-path profile. The supervisor logs
/// [`Self::summary`] and consults [`SpecAssessment`] before starting
/// the forwarding workers.
#[derive(Clone, Debug)]
pub struct CommodityProfile {
    /// Probed host shape.
    pub topology: HostTopology,
    /// Result of the [`COMMODITY_BASELINE`] preflight.
    pub assessment: SpecAssessment,
    /// Worker-thread affinity plan.
    pub affinity: AffinityPlan,
    /// Data-path (eBPF fast-path flag) profile.
    pub datapath: DataPathProfile,
}

impl CommodityProfile {
    /// Probe the host, assess it against the commodity baseline, and
    /// build the affinity + data-path plans.
    ///
    /// `data_dir` is the edge's spool directory (for the storage
    /// probe); `workers` is the number of forwarding worker threads to
    /// place; `datapath` is the *resolved* data-path backend.
    #[must_use]
    pub fn detect(data_dir: &Path, workers: usize, datapath: DataPathSelection) -> Self {
        let topology = HostTopology::detect(data_dir);
        let assessment = COMMODITY_BASELINE.assess(&topology);
        let affinity = AffinityPlan::compute(&topology, workers);
        let datapath = DataPathProfile::from_selection(datapath);
        Self {
            topology,
            assessment,
            affinity,
            datapath,
        }
    }

    /// A one-line, log-friendly summary of the profile.
    #[must_use]
    pub fn summary(&self) -> String {
        let assessment = match &self.assessment {
            SpecAssessment::Pass => "pass".to_owned(),
            SpecAssessment::Warn(r) => format!("warn ({})", r.join("; ")),
            SpecAssessment::Fail(r) => format!("FAIL ({})", r.join("; ")),
        };
        format!(
            "cpus={} numa_nodes={} mem={} storage_free={} workers={} datapath={:?} xdp={} \
             pool_frames={} min_spec={}",
            self.topology.logical_cpus,
            self.topology.numa_node_count(),
            human_bytes(self.topology.total_memory_bytes),
            human_bytes(self.topology.data_dir_available_bytes),
            self.affinity.assignments().len(),
            self.datapath.backend,
            self.datapath.xdp_fast_path,
            self.datapath.recommended_frame_count(),
            assessment,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpulist_ranges_and_singletons() {
        assert_eq!(parse_cpulist("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpulist("0,2,4"), vec![0, 2, 4]);
        assert_eq!(parse_cpulist("0-1,4,6-7"), vec![0, 1, 4, 6, 7]);
        assert_eq!(parse_cpulist(""), Vec::<usize>::new());
        // Malformed fragments are skipped, not fatal.
        assert_eq!(parse_cpulist("0-1,bogus,3"), vec![0, 1, 3]);
    }

    #[test]
    fn parse_meminfo_total() {
        let sample = "MemTotal:       16317840 kB\nMemFree: 100 kB\n";
        assert_eq!(parse_meminfo_total_bytes(sample), 16_317_840 * 1024);
        assert_eq!(parse_meminfo_total_bytes("MemFree: 1 kB\n"), 0);
    }

    fn topo(cpus: usize, nodes: Vec<NumaNode>, mem: u64, storage: u64) -> HostTopology {
        HostTopology {
            logical_cpus: cpus,
            numa_nodes: nodes,
            total_memory_bytes: mem,
            data_dir_available_bytes: storage,
        }
    }

    #[test]
    fn assess_pass_when_above_floor() {
        let t = topo(4, vec![uniform_node(4)], 4 * GIB, 32 * GIB);
        assert_eq!(COMMODITY_BASELINE.assess(&t), SpecAssessment::Pass);
    }

    #[test]
    fn assess_fail_on_too_few_cpus() {
        let t = topo(1, vec![uniform_node(1)], 4 * GIB, 32 * GIB);
        let a = COMMODITY_BASELINE.assess(&t);
        assert!(a.is_fail(), "want Fail, got {a:?}");
    }

    #[test]
    fn assess_fail_on_low_memory() {
        let t = topo(4, vec![uniform_node(4)], GIB, 32 * GIB);
        assert!(COMMODITY_BASELINE.assess(&t).is_fail());
    }

    #[test]
    fn assess_warn_on_low_storage_only() {
        let t = topo(4, vec![uniform_node(4)], 4 * GIB, GIB);
        match COMMODITY_BASELINE.assess(&t) {
            SpecAssessment::Warn(reasons) => {
                assert!(reasons.iter().any(|r| r.contains("storage")), "{reasons:?}");
            }
            other => panic!("want Warn, got {other:?}"),
        }
    }

    #[test]
    fn assess_warn_on_unprobed_metrics() {
        // CPUs satisfy the floor but memory/storage probed as unknown.
        let t = topo(2, vec![uniform_node(2)], 0, 0);
        match COMMODITY_BASELINE.assess(&t) {
            SpecAssessment::Warn(reasons) => assert_eq!(reasons.len(), 2, "{reasons:?}"),
            other => panic!("want Warn, got {other:?}"),
        }
    }

    #[test]
    fn affinity_one_cpu_per_worker_single_node() {
        let t = topo(4, vec![uniform_node(4)], 4 * GIB, 32 * GIB);
        let plan = AffinityPlan::compute(&t, 4);
        let cpus: Vec<usize> = plan.assignments().iter().map(|a| a.cpus[0]).collect();
        assert_eq!(cpus, vec![0, 1, 2, 3], "each worker its own CPU");
        assert!(plan.assignments().iter().all(|a| a.numa_node == 0));
    }

    #[test]
    fn affinity_spreads_across_numa_nodes() {
        let nodes = vec![
            NumaNode {
                id: 0,
                cpus: vec![0, 1],
            },
            NumaNode {
                id: 1,
                cpus: vec![2, 3],
            },
        ];
        let t = topo(4, nodes, 8 * GIB, 64 * GIB);
        let plan = AffinityPlan::compute(&t, 4);
        let a = plan.assignments();
        // Round-robin nodes: w0->node0, w1->node1, w2->node0, w3->node1.
        assert_eq!(a[0].numa_node, 0);
        assert_eq!(a[1].numa_node, 1);
        assert_eq!(a[2].numa_node, 0);
        assert_eq!(a[3].numa_node, 1);
        // Each worker's CPU is local to its node.
        assert!(a[0].cpus[0] == 0 || a[0].cpus[0] == 1);
        assert!(a[1].cpus[0] == 2 || a[1].cpus[0] == 3);
        // The two workers on node 0 take distinct CPUs.
        assert_ne!(a[0].cpus[0], a[2].cpus[0]);
    }

    #[test]
    fn affinity_clamps_zero_workers_to_one() {
        let t = topo(2, vec![uniform_node(2)], 2 * GIB, 8 * GIB);
        assert_eq!(AffinityPlan::compute(&t, 0).assignments().len(), 1);
    }

    #[test]
    fn affinity_pin_unknown_worker_errors() {
        let t = topo(2, vec![uniform_node(2)], 2 * GIB, 8 * GIB);
        let plan = AffinityPlan::compute(&t, 1);
        assert_eq!(
            plan.pin_current_thread(9),
            Err(AffinityError::UnknownWorker(9))
        );
    }

    #[test]
    fn buffer_pool_acquire_release_reuse() {
        let pool = MmapBufferPool::new(2048, 3).expect("map pool");
        assert_eq!(pool.capacity(), 3);
        assert_eq!(pool.frame_size(), 2048);
        assert_eq!(pool.frames_in_use(), 0);

        let a = pool.acquire().expect("frame a");
        let b = pool.acquire().expect("frame b");
        let c = pool.acquire().expect("frame c");
        assert_eq!(pool.frames_in_use(), 3);
        // Exhausted.
        assert!(pool.acquire().is_none());
        // Distinct, non-overlapping slots.
        assert_ne!(a.index(), b.index());
        assert_ne!(b.index(), c.index());

        drop(b);
        assert_eq!(pool.frames_in_use(), 2);
        // A freed slot is handed back out.
        let d = pool.acquire().expect("frame d after release");
        assert_eq!(pool.frames_in_use(), 3);
        drop(a);
        drop(c);
        drop(d);
        assert_eq!(pool.frames_in_use(), 0);
    }

    #[test]
    fn buffer_pool_frames_are_independent_memory() {
        let pool = MmapBufferPool::new(64, 2).expect("map pool");
        let mut f0 = pool.acquire().expect("f0");
        let mut f1 = pool.acquire().expect("f1");
        f0.as_mut_slice().fill(0xAA);
        f1.as_mut_slice().fill(0x55);
        // Writing one frame must not bleed into the other.
        assert!(f0.as_slice().iter().all(|&b| b == 0xAA));
        assert!(f1.as_slice().iter().all(|&b| b == 0x55));
    }

    #[test]
    fn buffer_pool_rejects_zero_dimensions() {
        assert!(matches!(
            MmapBufferPool::new(0, 4),
            Err(BufferPoolError::ZeroSized)
        ));
        assert!(matches!(
            MmapBufferPool::new(2048, 0),
            Err(BufferPoolError::ZeroSized)
        ));
    }

    #[test]
    fn datapath_profile_sizes_by_backend() {
        let ebpf = DataPathProfile::from_selection(DataPathSelection::Ebpf);
        assert!(ebpf.xdp_fast_path);
        assert_eq!(
            ebpf.recommended_frame_count(),
            DataPathProfile::FAST_PATH_FRAMES
        );

        let nft = DataPathProfile::from_selection(DataPathSelection::Nftables);
        assert!(!nft.xdp_fast_path);
        assert_eq!(
            nft.recommended_frame_count(),
            DataPathProfile::SLOW_PATH_FRAMES
        );
    }

    #[test]
    fn datapath_profile_allocates_pool() {
        let profile = DataPathProfile::from_selection(DataPathSelection::Nftables);
        let pool = profile.allocate_pool().expect("allocate pool");
        assert_eq!(pool.capacity(), DataPathProfile::SLOW_PATH_FRAMES);
        assert_eq!(pool.frame_size(), DataPathProfile::FRAME_BYTES);
    }

    #[test]
    fn commodity_profile_detect_is_consistent() {
        let dir = std::env::temp_dir();
        let profile = CommodityProfile::detect(&dir, 2, DataPathSelection::Nftables);
        // available_parallelism always reports >= 1.
        assert!(profile.topology.logical_cpus >= 1);
        assert_eq!(profile.affinity.assignments().len(), 2);
        assert!(!profile.datapath.xdp_fast_path);
        // Summary is a single line.
        assert!(!profile.summary().contains('\n'));
        assert!(profile.summary().contains("datapath="));
    }
}
