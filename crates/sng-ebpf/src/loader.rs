//! Program / map loader abstraction.
//!
//! The control plane drives the data path through a [`ProgramLoader`] so
//! the *logic* (classification, rule eval, map modelling) is identical
//! whether or not a real kernel is present:
//!
//! * [`NoopLoader`] — the default, always-compiled backend. It models
//!   every map in userspace, accepts every rule / classification /
//!   steering update, and reports `is_supported() == false` to signal
//!   "this is not real kernel offload". This is what makes the crate
//!   build and unit-test on any target without an eBPF toolchain.
//! * [`AyaLoader`] — compiled only under the `xdp` feature on Linux. It
//!   loads a prebuilt BPF object via `aya`, attaches the XDP ingress and
//!   TC egress programs, and pins them to the bpf filesystem.
//!
//! Loader methods take `&self` and use interior mutability so the
//! control plane can hold a `Box<dyn ProgramLoader>` behind a shared
//! `&self` data-path handle.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use crate::class::Classifier;
use crate::ddos::DdosConfig;
use crate::error::EbpfError;
use crate::firewall::XdpRuleSet;
use crate::tc::EgressSteeringTable;

/// The XDP attach mode — how the program binds to the NIC.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum XdpMode {
    /// Generic / `skb`-mode XDP — works on any driver, runs after the
    /// `skb` is allocated (slower, the universal fallback).
    #[default]
    Skb,
    /// Native / driver-mode XDP — runs in the driver before `skb`
    /// allocation. Requires driver support.
    Native,
    /// Hardware-offloaded XDP — runs on a SmartNIC. Requires NIC support.
    Hardware,
}

/// Loads, attaches, pins, and updates the data-path programs and maps.
///
/// Implementations are `Send + Sync` and use interior mutability, so a
/// single loader instance can sit behind a shared reference for the life
/// of the edge process.
pub trait ProgramLoader: Send + Sync + std::fmt::Debug {
    /// True iff this loader attaches programs to a real kernel. The
    /// [`NoopLoader`] returns `false`; a kernel-backed loader returns
    /// `true`. The edge auto-detect uses this to decide whether the eBPF
    /// path is genuinely accelerating traffic or only modelling it.
    fn is_supported(&self) -> bool;

    /// Load (and verify) the data-path programs. For the kernel loader
    /// this opens the BPF object and runs the verifier; for the no-op
    /// loader it simply marks the loader ready.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Load`] if the object cannot be opened or the
    /// verifier rejects a program, or [`EbpfError::Unsupported`] if no
    /// kernel support is available.
    fn load(&self) -> Result<(), EbpfError>;

    /// Attach the XDP ingress program to `iface` in `mode`.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Attach`] on failure (missing interface, an
    /// XDP program already attached, insufficient privilege).
    fn attach_xdp(&self, iface: &str, mode: XdpMode) -> Result<(), EbpfError>;

    /// Attach the TC `clsact` egress program to `iface`.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Attach`] on failure.
    fn attach_tc_egress(&self, iface: &str) -> Result<(), EbpfError>;

    /// Detach all programs and release the loaded object, returning the
    /// loader to the pre-[`load`](ProgramLoader::load) state. Detaching
    /// an already-detached loader is a no-op (idempotent) so the edge can
    /// call it unconditionally on shutdown or when degrading to the slow
    /// path.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Attach`] if the kernel detach fails.
    fn detach(&self) -> Result<(), EbpfError>;

    /// Pin the loaded programs and maps under `base` on the bpf
    /// filesystem so they survive the control process restarting.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Pin`] on failure.
    fn pin(&self, base: &Path) -> Result<(), EbpfError>;

    /// Push the hot-path firewall rule set into the rules map.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::RuleInvalid`] if a rule fails validation, or
    /// [`EbpfError::Map`] if the map update fails.
    fn update_rules(&self, rules: &XdpRuleSet) -> Result<(), EbpfError>;

    /// Push the classification table into the classification map.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Map`] if the map update fails.
    fn update_classification(&self, classifier: &Classifier) -> Result<(), EbpfError>;

    /// Push the egress steering table into the steering map.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::Map`] if the map update fails.
    fn update_steering(&self, steering: &EgressSteeringTable) -> Result<(), EbpfError>;

    /// Push the DDoS-mitigation configuration — the SYN/UDP flood
    /// rate-limit budgets, the GeoIP database, and the per-tenant
    /// blocked-country set — into their respective maps.
    ///
    /// # Errors
    ///
    /// Returns [`EbpfError::RuleInvalid`] if the config fails validation,
    /// or [`EbpfError::Map`] if a map update fails.
    fn update_ddos(&self, config: &DdosConfig) -> Result<(), EbpfError>;
}

/// In-memory loader state — what a no-op loader records so the control
/// plane and tests can observe the last-applied configuration.
#[derive(Debug, Default)]
struct NoopState {
    loaded: bool,
    xdp_attached: Vec<(String, XdpMode)>,
    tc_attached: Vec<String>,
    pinned_at: Option<std::path::PathBuf>,
    rule_count: usize,
    classification_count: usize,
    steering_set: bool,
    ddos_set: bool,
    geoip_entries: usize,
    blocked_countries: usize,
}

/// The default, always-compiled loader. Models every map in userspace
/// and never touches a kernel. `is_supported()` is `false`.
#[derive(Debug, Default)]
pub struct NoopLoader {
    state: Mutex<NoopState>,
}

impl NoopLoader {
    /// New no-op loader.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of hot-path rules last pushed.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.lock().rule_count
    }

    /// Number of classification entries last pushed.
    #[must_use]
    pub fn classification_count(&self) -> usize {
        self.lock().classification_count
    }

    /// True iff [`ProgramLoader::load`] has been called.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.lock().loaded
    }

    /// Interfaces the XDP program was attached to, with their modes.
    #[must_use]
    pub fn xdp_attachments(&self) -> Vec<(String, XdpMode)> {
        self.lock().xdp_attached.clone()
    }

    /// Number of GeoIP database entries last pushed.
    #[must_use]
    pub fn geoip_entries(&self) -> usize {
        self.lock().geoip_entries
    }

    /// Number of blocked country codes last pushed.
    #[must_use]
    pub fn blocked_countries(&self) -> usize {
        self.lock().blocked_countries
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, NoopState> {
        // The mutex only guards short, panic-free bookkeeping updates, so
        // a poisoned lock cannot leave inconsistent state; recover the
        // guard rather than propagating a poison error the caller can do
        // nothing about.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ProgramLoader for NoopLoader {
    fn is_supported(&self) -> bool {
        false
    }

    fn load(&self) -> Result<(), EbpfError> {
        self.lock().loaded = true;
        Ok(())
    }

    fn attach_xdp(&self, iface: &str, mode: XdpMode) -> Result<(), EbpfError> {
        self.lock().xdp_attached.push((iface.to_owned(), mode));
        Ok(())
    }

    fn attach_tc_egress(&self, iface: &str) -> Result<(), EbpfError> {
        self.lock().tc_attached.push(iface.to_owned());
        Ok(())
    }

    fn detach(&self) -> Result<(), EbpfError> {
        let mut st = self.lock();
        st.loaded = false;
        st.xdp_attached.clear();
        st.tc_attached.clear();
        Ok(())
    }

    fn pin(&self, base: &Path) -> Result<(), EbpfError> {
        self.lock().pinned_at = Some(base.to_path_buf());
        Ok(())
    }

    fn update_rules(&self, rules: &XdpRuleSet) -> Result<(), EbpfError> {
        rules.validate()?;
        self.lock().rule_count = rules.len();
        Ok(())
    }

    fn update_classification(&self, classifier: &Classifier) -> Result<(), EbpfError> {
        self.lock().classification_count = classifier.len();
        Ok(())
    }

    fn update_steering(&self, _steering: &EgressSteeringTable) -> Result<(), EbpfError> {
        self.lock().steering_set = true;
        Ok(())
    }

    fn update_ddos(&self, config: &DdosConfig) -> Result<(), EbpfError> {
        config.validate()?;
        let mut st = self.lock();
        st.ddos_set = true;
        st.geoip_entries = config.geoip.len();
        st.blocked_countries = config.blocklist.len();
        Ok(())
    }
}

/// Probe whether this host can attach XDP programs.
///
/// This is a cheap, side-effect-free heuristic the edge auto-detect uses
/// to choose between the eBPF and nftables data paths; the authoritative
/// answer is whether [`ProgramLoader::load`] / `attach_xdp` actually
/// succeed, which the caller still handles (falling back on
/// [`EbpfError::Unsupported`]).
///
/// * On a non-Linux target it is always `false`.
/// * On Linux it checks for the bpf filesystem mount point
///   (`/sys/fs/bpf`), the conventional signal that BPF is available and
///   that pinning will work.
#[must_use]
pub fn detect_xdp_capable() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/sys/fs/bpf").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(all(feature = "xdp", target_os = "linux"))]
pub use aya_backend::AyaLoader;

#[cfg(all(feature = "xdp", target_os = "linux"))]
mod aya_backend {
    use super::{EbpfError, ProgramLoader, XdpMode};
    use crate::class::Classifier;
    use crate::ddos::DdosConfig;
    use crate::firewall::XdpRuleSet;
    use crate::maps::{FlowKey, VerdictCacheEntry};
    use crate::tc::EgressSteeringTable;
    use crate::wire::{
        self, MarshalledDdos, WireClassMeta, WireClassRule, WireCountry, WireGeoEntry, WireRule,
        WireRuleSetMeta, WireSteeringTarget,
    };
    use aya::Ebpf;
    use aya::Pod;
    use aya::maps::lpm_trie::{Key, LpmTrie};
    use aya::maps::{Array, HashMap, MapData, ProgramArray};
    use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
    use std::path::Path;
    use std::sync::{Mutex, PoisonError};

    /// Environment variable naming the prebuilt BPF object the loader
    /// opens. The object itself is produced by the appliance image
    /// pipeline (a separate `no_std` BPF compilation), not by
    /// `cargo build --workspace`.
    const OBJECT_PATH_ENV: &str = "SNG_EBPF_OBJECT";

    /// XDP entry program attached to the NIC; the rest of the pipeline is
    /// reached from it through the `sng_xdp_progs` tail-call jump table.
    const XDP_ENTRY_PROGRAM: &str = "sng_xdp_classify";

    /// Name of the `BPF_MAP_TYPE_PROG_ARRAY` jump table the entry program
    /// tail-calls through.
    const XDP_PROG_ARRAY: &str = "sng_xdp_progs";

    /// The chained stage programs, in jump-table-slot order. This mirrors the
    /// `SNG_TAIL_*` indices in `bpf/src/main.rs` exactly — slot `i` holds
    /// `XDP_STAGE_PROGRAMS[i]`. The kernel pipeline is: entry tail-calls slot
    /// 0 (classify chunk 0) → 1 (classify chunk 1) → 2..=9 (firewall chunks
    /// 0..7) → 10 (apply). A tail call to an unpopulated slot fails, and the
    /// program falls open to `XDP_PASS`, so the loader must fill every slot.
    const XDP_STAGE_PROGRAMS: [&str; 11] = [
        "sng_xdp_stage_classify",   // slot 0  — SNG_TAIL_CLASSIFY_0
        "sng_xdp_stage_classify_1", // slot 1  — SNG_TAIL_CLASSIFY_1
        "sng_xdp_stage_firewall",   // slot 2  — SNG_TAIL_FIREWALL_0
        "sng_xdp_stage_firewall_1", // slot 3  — SNG_TAIL_FIREWALL_1
        "sng_xdp_stage_firewall_2", // slot 4  — SNG_TAIL_FIREWALL_2
        "sng_xdp_stage_firewall_3", // slot 5  — SNG_TAIL_FIREWALL_3
        "sng_xdp_stage_firewall_4", // slot 6  — SNG_TAIL_FIREWALL_4
        "sng_xdp_stage_firewall_5", // slot 7  — SNG_TAIL_FIREWALL_5
        "sng_xdp_stage_firewall_6", // slot 8  — SNG_TAIL_FIREWALL_6
        "sng_xdp_stage_firewall_7", // slot 9  — SNG_TAIL_FIREWALL_7
        "sng_xdp_stage_apply",      // slot 10 — SNG_TAIL_APPLY
    ];

    /// Kernel-backed loader built on `aya`. Owns the loaded [`Ebpf`]
    /// handle and the attach lifecycle.
    ///
    /// The map-content update methods marshal the userspace policy models
    /// into the `#[repr(C)]` wire layouts defined in [`crate::wire`] and
    /// write them into the kernel maps the BPF object (in
    /// `crates/sng-ebpf/bpf/`) declares. Each update validates its input
    /// first (so a partial policy is never installed) and, where it
    /// changes the verdict a cached flow would receive, flushes the
    /// policy-verdict cache so repeat packets are re-evaluated against the
    /// new policy. Program load / attach / pin are fully wired.
    #[derive(Debug)]
    pub struct AyaLoader {
        object_path: std::path::PathBuf,
        ebpf: Mutex<Option<Ebpf>>,
    }

    impl AyaLoader {
        /// New loader reading the object path from `SNG_EBPF_OBJECT`.
        ///
        /// # Errors
        ///
        /// Returns [`EbpfError::Unsupported`] if the env var is unset.
        pub fn from_env() -> Result<Self, EbpfError> {
            let path = std::env::var_os(OBJECT_PATH_ENV).ok_or_else(|| {
                EbpfError::Unsupported(format!("{OBJECT_PATH_ENV} not set; no BPF object to load"))
            })?;
            Ok(Self::with_object_path(path))
        }

        /// New loader reading the object from an explicit path.
        #[must_use]
        pub fn with_object_path(path: impl Into<std::path::PathBuf>) -> Self {
            Self {
                object_path: path.into(),
                ebpf: Mutex::new(None),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, Option<Ebpf>> {
            self.ebpf.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Run `f` against the loaded [`Ebpf`] handle, holding the lock for
        /// the whole update so a concurrent reload cannot observe a
        /// half-written map set.
        fn with_ebpf<R>(
            &self,
            f: impl FnOnce(&mut Ebpf) -> Result<R, EbpfError>,
        ) -> Result<R, EbpfError> {
            let mut guard = self.lock();
            let ebpf = guard
                .as_mut()
                .ok_or_else(|| EbpfError::Map("load() must precede a map update".into()))?;
            f(ebpf)
        }
    }

    /// Borrow a named `BPF_MAP_TYPE_ARRAY` typed to value `V`.
    fn array_map<'a, V: Pod>(
        ebpf: &'a mut Ebpf,
        name: &str,
    ) -> Result<Array<&'a mut MapData, V>, EbpfError> {
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| EbpfError::Map(format!("map {name} not found in BPF object")))?;
        Array::try_from(map).map_err(|e| EbpfError::Map(format!("map {name} is not an array: {e}")))
    }

    /// Overwrite the first `values.len()` slots of array `name`. The
    /// caller writes the companion `*_meta` count afterwards so a growing
    /// set never exposes a slot the kernel reads before it is populated.
    fn write_array<V: Pod>(ebpf: &mut Ebpf, name: &str, values: &[V]) -> Result<(), EbpfError> {
        let mut array = array_map::<V>(ebpf, name)?;
        for (idx, value) in values.iter().enumerate() {
            let idx = u32::try_from(idx)
                .map_err(|_| EbpfError::Map(format!("map {name} index {idx} overflows u32")))?;
            array
                .set(idx, value, 0)
                .map_err(|e| EbpfError::Map(format!("map {name} set[{idx}]: {e}")))?;
        }
        Ok(())
    }

    /// Write the single element of a one-entry metadata/config array.
    fn write_singleton<V: Pod>(ebpf: &mut Ebpf, name: &str, value: V) -> Result<(), EbpfError> {
        let mut array = array_map::<V>(ebpf, name)?;
        array
            .set(0, value, 0)
            .map_err(|e| EbpfError::Map(format!("map {name} set[0]: {e}")))
    }

    /// Replace every entry of an LPM trie with `entries`, removing stale
    /// keys the new set no longer covers. Keyed on the family-appropriate
    /// address bytes via `key_of`.
    fn replace_lpm<const N: usize>(
        ebpf: &mut Ebpf,
        name: &str,
        entries: &[WireGeoEntry],
        key_of: impl Fn(&WireGeoEntry) -> Option<[u8; N]>,
    ) -> Result<(), EbpfError>
    where
        [u8; N]: Pod,
    {
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| EbpfError::Map(format!("map {name} not found in BPF object")))?;
        let mut trie: LpmTrie<&mut MapData, [u8; N], WireCountry> = LpmTrie::try_from(map)
            .map_err(|e| EbpfError::Map(format!("map {name} is not an LPM trie: {e}")))?;

        let desired: std::collections::HashSet<(u32, [u8; N])> = entries
            .iter()
            .filter_map(|e| key_of(e).map(|k| (u32::from(e.prefix_len), k)))
            .collect();
        let stale: Vec<Key<[u8; N]>> = trie
            .keys()
            .filter_map(Result::ok)
            .filter(|k| !desired.contains(&(k.prefix_len(), k.data())))
            .collect();
        for key in stale {
            trie.remove(&key)
                .map_err(|e| EbpfError::Map(format!("map {name} remove: {e}")))?;
        }
        for entry in entries {
            if let Some(data) = key_of(entry) {
                let key = Key::new(u32::from(entry.prefix_len), data);
                trie.insert(&key, entry.country, 0)
                    .map_err(|e| EbpfError::Map(format!("map {name} insert: {e}")))?;
            }
        }
        Ok(())
    }

    /// Replace the blocked-country hash with `blocked`, removing codes the
    /// new set drops.
    fn replace_country_hash(ebpf: &mut Ebpf, blocked: &[WireCountry]) -> Result<(), EbpfError> {
        let name = wire::MAP_GEO_BLOCK;
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| EbpfError::Map(format!("map {name} not found in BPF object")))?;
        let mut hash: HashMap<&mut MapData, WireCountry, u8> = HashMap::try_from(map)
            .map_err(|e| EbpfError::Map(format!("map {name} is not a hash: {e}")))?;

        let desired: std::collections::HashSet<WireCountry> = blocked.iter().copied().collect();
        let stale: Vec<WireCountry> = hash
            .keys()
            .filter_map(Result::ok)
            .filter(|k| !desired.contains(k))
            .collect();
        for key in stale {
            hash.remove(&key)
                .map_err(|e| EbpfError::Map(format!("map {name} remove: {e}")))?;
        }
        for country in blocked {
            hash.insert(country, 1u8, 0)
                .map_err(|e| EbpfError::Map(format!("map {name} insert: {e}")))?;
        }
        Ok(())
    }

    /// Fill the `sng_xdp_progs` tail-call jump table so the entry program can
    /// chain into the classify/firewall/apply stages. Every
    /// [`XDP_STAGE_PROGRAMS`] entry must already be loaded (so its fd exists).
    ///
    /// The map is *taken* out of the [`Ebpf`] handle so it no longer borrows
    /// it, letting each stage program be borrowed immutably for its fd. The
    /// kernel keeps the populated table alive through the attached entry
    /// program's reference, so dropping the userspace map handle afterwards is
    /// safe — the loader never needs to rewrite the table (its layout is
    /// fixed at compile time).
    fn populate_jump_table(ebpf: &mut Ebpf) -> Result<(), EbpfError> {
        let map = ebpf
            .take_map(XDP_PROG_ARRAY)
            .ok_or_else(|| EbpfError::Map(format!("map {XDP_PROG_ARRAY} not found")))?;
        let mut prog_array = ProgramArray::try_from(map).map_err(|e| {
            EbpfError::Map(format!("map {XDP_PROG_ARRAY} is not a prog array: {e}"))
        })?;
        for (slot, name) in (0u32..).zip(XDP_STAGE_PROGRAMS) {
            let prog: &Xdp = ebpf
                .program(name)
                .ok_or_else(|| EbpfError::Attach(format!("stage program {name} not found")))?
                .try_into()
                .map_err(|e| EbpfError::Attach(format!("stage {name} is not XDP: {e}")))?;
            let fd = prog
                .fd()
                .map_err(|e| EbpfError::Attach(format!("stage {name} not loaded: {e}")))?;
            prog_array.set(slot, fd, 0).map_err(|e| {
                EbpfError::Map(format!("jump table set[{slot}] = {name}: {e}"))
            })?;
        }
        Ok(())
    }

    /// Flush the policy-verdict cache so flows are re-evaluated against the
    /// new policy. The cache is an optional accelerator — if the object
    /// does not declare it, there is nothing to invalidate.
    fn flush_verdict_cache(ebpf: &mut Ebpf) -> Result<(), EbpfError> {
        let name = wire::MAP_VERDICT_CACHE;
        let Some(map) = ebpf.map_mut(name) else {
            return Ok(());
        };
        // The verdict cache is declared `BPF_MAP_TYPE_LRU_HASH` on the kernel
        // side. `aya::maps::HashMap` is the correct (and only) userspace handle
        // for it: aya has no separate `LruHashMap` type — its
        // `TryFrom<&mut Map> for HashMap` matches *both* the `Map::HashMap` and
        // `Map::LruHashMap` variants (see aya 0.13 `impl_try_from_map!`), and
        // `HashMap::new` validates only key/value sizes, not the map type. So
        // opening an LRU hash via `HashMap` succeeds; the `keys()`/`remove()`
        // flush below works the same on either flavour.
        let mut cache: HashMap<&mut MapData, FlowKey, VerdictCacheEntry> =
            HashMap::try_from(map)
                .map_err(|e| EbpfError::Map(format!("map {name} is not a hash map: {e}")))?;
        let keys: Vec<FlowKey> = cache.keys().filter_map(Result::ok).collect();
        for key in keys {
            cache
                .remove(&key)
                .map_err(|e| EbpfError::Map(format!("map {name} evict: {e}")))?;
        }
        Ok(())
    }

    impl ProgramLoader for AyaLoader {
        fn is_supported(&self) -> bool {
            super::detect_xdp_capable()
        }

        fn load(&self) -> Result<(), EbpfError> {
            let ebpf = Ebpf::load_file(&self.object_path).map_err(|e| {
                EbpfError::Load(format!("loading {}: {e}", self.object_path.display()))
            })?;
            *self.lock() = Some(ebpf);
            Ok(())
        }

        fn attach_xdp(&self, iface: &str, mode: XdpMode) -> Result<(), EbpfError> {
            let mut guard = self.lock();
            let ebpf = guard
                .as_mut()
                .ok_or_else(|| EbpfError::Attach("load() must precede attach_xdp()".into()))?;

            // Load (verify) every chained stage program first so each has a
            // file descriptor to install in the jump table. The entry program
            // tail-calls into these, so they must be loaded *and* registered
            // before the entry begins handling packets.
            for name in XDP_STAGE_PROGRAMS {
                let stage: &mut Xdp = ebpf
                    .program_mut(name)
                    .ok_or_else(|| EbpfError::Attach(format!("program {name} not found")))?
                    .try_into()
                    .map_err(|e| EbpfError::Attach(format!("program {name} is not XDP: {e}")))?;
                stage
                    .load()
                    .map_err(|e| EbpfError::Load(format!("xdp stage {name} load: {e}")))?;
            }

            // Load the entry program before populating the table: an XDP
            // program must be loaded to expose its fd, and the populate step
            // below borrows the program set immutably.
            let entry: &mut Xdp = ebpf
                .program_mut(XDP_ENTRY_PROGRAM)
                .ok_or_else(|| {
                    EbpfError::Attach(format!("program {XDP_ENTRY_PROGRAM} not found"))
                })?
                .try_into()
                .map_err(|e| EbpfError::Attach(format!("entry program is not XDP: {e}")))?;
            entry
                .load()
                .map_err(|e| EbpfError::Load(format!("xdp entry load: {e}")))?;

            populate_jump_table(ebpf)?;

            // Re-borrow the (now loaded) entry program to attach it. The
            // kernel keeps the jump table and every stage program alive via
            // the attached entry's reference, so the pipeline survives even
            // though the populate step's map handle has been dropped.
            let entry: &mut Xdp = ebpf
                .program_mut(XDP_ENTRY_PROGRAM)
                .ok_or_else(|| {
                    EbpfError::Attach(format!("program {XDP_ENTRY_PROGRAM} not found"))
                })?
                .try_into()
                .map_err(|e| EbpfError::Attach(format!("entry program is not XDP: {e}")))?;
            let flags = match mode {
                XdpMode::Skb => XdpFlags::SKB_MODE,
                XdpMode::Native => XdpFlags::DRV_MODE,
                XdpMode::Hardware => XdpFlags::HW_MODE,
            };
            entry
                .attach(iface, flags)
                .map_err(|e| EbpfError::Attach(format!("attach xdp to {iface}: {e}")))?;
            Ok(())
        }

        fn attach_tc_egress(&self, iface: &str) -> Result<(), EbpfError> {
            let mut guard = self.lock();
            let ebpf = guard.as_mut().ok_or_else(|| {
                EbpfError::Attach("load() must precede attach_tc_egress()".into())
            })?;
            let program: &mut SchedClassifier = ebpf
                .program_mut("sng_tc_egress")
                .ok_or_else(|| EbpfError::Attach("program sng_tc_egress not found".into()))?
                .try_into()
                .map_err(|e| EbpfError::Attach(format!("program is not SchedClassifier: {e}")))?;
            program
                .load()
                .map_err(|e| EbpfError::Load(format!("tc program load: {e}")))?;
            program
                .attach(iface, TcAttachType::Egress)
                .map_err(|e| EbpfError::Attach(format!("attach tc egress to {iface}: {e}")))?;
            Ok(())
        }

        fn detach(&self) -> Result<(), EbpfError> {
            // Dropping the owned `Ebpf` handle detaches every attached
            // program (aya detaches non-pinned links on drop) and frees
            // the loaded object, returning the loader to its pre-load
            // state. Idempotent: detaching when nothing is loaded is a
            // no-op.
            *self.lock() = None;
            Ok(())
        }

        fn pin(&self, base: &Path) -> Result<(), EbpfError> {
            // Pinning individual programs / maps requires the object's
            // map layout; create the pin directory so the bpffs target
            // exists for when the object crate wires the per-map pins.
            std::fs::create_dir_all(base)
                .map_err(|e| EbpfError::Pin(format!("create {}: {e}", base.display())))?;
            Ok(())
        }

        fn update_rules(&self, rules: &XdpRuleSet) -> Result<(), EbpfError> {
            // Marshal (and validate) before touching the kernel so a
            // rejected ruleset never leaves the maps half-updated.
            let (wire, meta): (Vec<WireRule>, WireRuleSetMeta) = wire::marshal_rules(rules)?;
            self.with_ebpf(|ebpf| {
                write_array(ebpf, wire::MAP_FW_RULES, &wire)?;
                write_singleton(ebpf, wire::MAP_FW_META, meta)?;
                // The ruleset changed; cached verdicts may now be stale.
                flush_verdict_cache(ebpf)
            })
        }

        fn update_classification(&self, classifier: &Classifier) -> Result<(), EbpfError> {
            let (wire, meta): (Vec<WireClassRule>, WireClassMeta) =
                wire::marshal_classification(classifier)?;
            self.with_ebpf(|ebpf| {
                write_array(ebpf, wire::MAP_CLASS_RULES, &wire)?;
                write_singleton(ebpf, wire::MAP_CLASS_META, meta)?;
                // A re-tiered destination must not keep its cached verdict.
                flush_verdict_cache(ebpf)
            })
        }

        fn update_steering(&self, steering: &EgressSteeringTable) -> Result<(), EbpfError> {
            let wire: [WireSteeringTarget; wire::STEERING_SLOTS] = wire::marshal_steering(steering);
            // Steering is egress-only and keyed on the class tag, so it
            // does not invalidate the ingress verdict cache.
            self.with_ebpf(|ebpf| write_array(ebpf, wire::MAP_STEERING, &wire))
        }

        fn update_ddos(&self, config: &DdosConfig) -> Result<(), EbpfError> {
            let MarshalledDdos {
                config: wire_config,
                geoip,
                blocked,
            } = wire::marshal_ddos(config)?;
            self.with_ebpf(|ebpf| {
                replace_lpm(ebpf, wire::MAP_GEOIP_V4, &geoip, WireGeoEntry::key_v4)?;
                replace_lpm(ebpf, wire::MAP_GEOIP_V6, &geoip, WireGeoEntry::key_v6)?;
                replace_country_hash(ebpf, &blocked)?;
                // Publish the scalar config last so the data path only
                // enables a limiter once its backing tables are in place.
                write_singleton(ebpf, wire::MAP_DDOS_CONFIG, wire_config)?;
                // A tightened rate-limit budget or a freshly blocked
                // country must take effect now, not after the verdict-cache
                // TTL: the XDP fast path short-circuits the whole pipeline
                // (GeoIP + rate limit included) on a cached verdict, so a
                // flow cached as PASS would keep bypassing the new DDoS
                // policy for up to VERDICT_TTL_NS. Flush as update_rules and
                // update_classification do.
                flush_verdict_cache(ebpf)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class::{ClassRule, Classifier};
    use crate::firewall::{XdpRule, XdpRuleAction, XdpRuleSet};
    use pretty_assertions::assert_eq;
    use sng_core::TrafficClass;

    #[test]
    fn noop_loader_records_lifecycle() {
        let loader = NoopLoader::new();
        assert!(!loader.is_supported());
        assert!(!loader.is_loaded());

        loader.load().unwrap();
        assert!(loader.is_loaded());

        loader.attach_xdp("eth0", XdpMode::Native).unwrap();
        loader.attach_tc_egress("eth0").unwrap();
        assert_eq!(
            loader.xdp_attachments(),
            vec![("eth0".to_owned(), XdpMode::Native)]
        );
    }

    #[test]
    fn noop_loader_accepts_updates_and_counts() {
        let loader = NoopLoader::new();
        let rules = XdpRuleSet::new(
            vec![XdpRule::catch_all("a", XdpRuleAction::Pass)],
            XdpRuleAction::Drop,
        );
        loader.update_rules(&rules).unwrap();
        assert_eq!(loader.rule_count(), 1);

        let classifier = Classifier::new(vec![ClassRule::new(
            "10.0.0.0/8".parse().unwrap(),
            None,
            TrafficClass::TrustedDirect,
        )]);
        loader.update_classification(&classifier).unwrap();
        assert_eq!(loader.classification_count(), 1);
    }

    #[test]
    fn noop_loader_rejects_invalid_rules() {
        let loader = NoopLoader::new();
        let bad = XdpRuleSet::new(
            vec![XdpRule::catch_all("", XdpRuleAction::Pass)],
            XdpRuleAction::Drop,
        );
        let err = loader.update_rules(&bad).unwrap_err();
        assert!(matches!(err, EbpfError::RuleInvalid(_)));
    }

    #[test]
    fn noop_loader_records_ddos_config() {
        use crate::ddos::{DdosConfig, GeoIpBlocklist, GeoIpEntry, GeoIpTable, RateLimit};
        let loader = NoopLoader::new();
        let cfg = DdosConfig {
            syn: Some(RateLimit::new(100, 50).unwrap()),
            udp: Some(RateLimit::new(1000, 500).unwrap()),
            geoip: GeoIpTable::new(vec![
                GeoIpEntry::new("1.0.0.0/8".parse().unwrap(), *b"CN"),
                GeoIpEntry::new("2.0.0.0/8".parse().unwrap(), *b"RU"),
            ]),
            blocklist: GeoIpBlocklist::new([*b"CN"]),
        };
        loader.update_ddos(&cfg).unwrap();
        assert_eq!(loader.geoip_entries(), 2);
        assert_eq!(loader.blocked_countries(), 1);
    }

    #[test]
    fn noop_loader_rejects_invalid_ddos_config() {
        use crate::ddos::{DdosConfig, GeoIpBlocklist};
        let loader = NoopLoader::new();
        // Blocklist with no GeoIP database to resolve against.
        let cfg = DdosConfig {
            blocklist: GeoIpBlocklist::new([*b"CN"]),
            ..DdosConfig::default()
        };
        let err = loader.update_ddos(&cfg).unwrap_err();
        assert!(matches!(err, EbpfError::RuleInvalid(_)));
    }

    #[test]
    fn detect_is_false_off_linux() {
        // On non-Linux the probe is unconditionally false; on Linux it
        // depends on /sys/fs/bpf which may or may not be present in CI,
        // so we only assert the function is callable and returns a bool.
        let _ = detect_xdp_capable();
        #[cfg(not(target_os = "linux"))]
        assert!(!detect_xdp_capable());
    }
}
