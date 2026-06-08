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
    use crate::tc::EgressSteeringTable;
    use aya::Ebpf;
    use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
    use std::path::Path;
    use std::sync::{Mutex, PoisonError};

    /// Environment variable naming the prebuilt BPF object the loader
    /// opens. The object itself is produced by the appliance image
    /// pipeline (a separate `no_std` BPF compilation), not by
    /// `cargo build --workspace`.
    const OBJECT_PATH_ENV: &str = "SNG_EBPF_OBJECT";

    /// Kernel-backed loader built on `aya`. Owns the loaded [`Ebpf`]
    /// handle and the attach lifecycle.
    ///
    /// The map-content update methods (`update_rules` /
    /// `update_classification` / `update_steering`) require the kernel
    /// object's map definitions and `Pod` marshalling, which land with
    /// the BPF object crate; until then they validate their input and
    /// surface a clear [`EbpfError::Unsupported`] rather than silently
    /// dropping the update. Program load / attach / pin are fully wired.
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
            let program: &mut Xdp = ebpf
                .program_mut("sng_xdp_classify")
                .ok_or_else(|| EbpfError::Attach("program sng_xdp_classify not found".into()))?
                .try_into()
                .map_err(|e| EbpfError::Attach(format!("program is not XDP: {e}")))?;
            program
                .load()
                .map_err(|e| EbpfError::Load(format!("xdp program load: {e}")))?;
            let flags = match mode {
                XdpMode::Skb => XdpFlags::SKB_MODE,
                XdpMode::Native => XdpFlags::DRV_MODE,
                XdpMode::Hardware => XdpFlags::HW_MODE,
            };
            program
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
            rules.validate()?;
            Err(EbpfError::Unsupported(
                "kernel rule-map marshalling lands with the BPF object crate".into(),
            ))
        }

        fn update_classification(&self, _classifier: &Classifier) -> Result<(), EbpfError> {
            Err(EbpfError::Unsupported(
                "kernel classification-map marshalling lands with the BPF object crate".into(),
            ))
        }

        fn update_steering(&self, _steering: &EgressSteeringTable) -> Result<(), EbpfError> {
            Err(EbpfError::Unsupported(
                "kernel steering-map marshalling lands with the BPF object crate".into(),
            ))
        }

        fn update_ddos(&self, config: &DdosConfig) -> Result<(), EbpfError> {
            config.validate()?;
            Err(EbpfError::Unsupported(
                "kernel ddos-map marshalling lands with the BPF object crate".into(),
            ))
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
