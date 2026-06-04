//! Virtual-IP (VIP) ownership.
//!
//! Exactly one instance in an HA pair owns the VIP at a time:
//! the Master. On promotion the Master adds the VIP to its
//! data-plane interface and announces the new owner with a
//! gratuitous ARP so the L2 segment re-points the MAC mapping
//! immediately (rather than waiting out the neighbours' ARP
//! cache TTL); on demotion it removes the address.
//!
//! ## Backend choice
//!
//! The Session-C spec suggests driving this "via netlink (the
//! `nix` crate)". A raw `RTM_NEWADDR` netlink exchange needs an
//! `unsafe` libc shim to lay out the `nlmsghdr` / `ifaddrmsg`
//! structs, which collides with the workspace's
//! `unsafe_code = "deny"` posture. Rather than carve out an
//! `#[allow(unsafe_code)]` island, this follows the pattern the
//! firewall plane already established for the same class of
//! kernel-state mutation: [`sng_fw`]'s `ShellNftables` shells
//! out to `nft`. [`ShellVipManager`] shells out to `ip` the same
//! way — `ip addr add/del` plus an `arping` gratuitous
//! announcement — so the privileged side-effect goes through one
//! auditable, well-understood binary and the crate stays
//! `unsafe`-free. This deviation is noted in the PR description.
//!
//! The kernel already emits a gratuitous ARP when an address is
//! added to an `up` interface; the explicit `arping -A` is a
//! belt-and-braces re-announcement and is treated as best-effort
//! (a missing `arping` binary is logged, not fatal).

use crate::error::{HaError, HaResult};
use async_trait::async_trait;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;

/// Default count of gratuitous ARP announcements to send on
/// acquire.
pub const DEFAULT_GRATUITOUS_ARP_COUNT: u8 = 3;

/// A virtual IP bound to an interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VipSpec {
    /// The virtual address.
    pub address: IpAddr,
    /// CIDR prefix length the address is configured with.
    pub prefix_len: u8,
    /// Interface the VIP lives on (e.g. `eth0`).
    pub interface: String,
}

impl VipSpec {
    /// Construct a VIP spec.
    #[must_use]
    pub fn new(address: IpAddr, prefix_len: u8, interface: impl Into<String>) -> Self {
        Self {
            address,
            prefix_len,
            interface: interface.into(),
        }
    }

    /// `address/prefix` in the form `ip addr` expects.
    #[must_use]
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.address, self.prefix_len)
    }

    /// Validate the spec.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::InvalidConfig`] for an empty interface
    /// name or a prefix length out of range for the address
    /// family.
    pub fn validate(&self) -> HaResult<()> {
        if self.interface.trim().is_empty() {
            return Err(HaError::InvalidConfig("vip interface is empty".into()));
        }
        let max = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix_len > max {
            return Err(HaError::InvalidConfig(format!(
                "vip prefix /{} out of range for address family (max /{max})",
                self.prefix_len
            )));
        }
        Ok(())
    }
}

/// Manages the VIP's presence on the local interface.
#[async_trait]
pub trait VipManager: Send + Sync + std::fmt::Debug {
    /// Add the VIP and announce ownership (gratuitous ARP).
    /// Idempotent: re-acquiring an address already present is
    /// not an error.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::Vip`] if adding the address fails.
    async fn acquire(&self, vip: &VipSpec) -> HaResult<()>;

    /// Remove the VIP from the interface. Idempotent: releasing
    /// an absent address is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::Vip`] if removing the address fails.
    async fn release(&self, vip: &VipSpec) -> HaResult<()>;
}

/// Build the `ip addr add` argument vector for `vip`. Factored
/// out so the exact command surface is unit-testable without
/// running `ip`.
#[must_use]
pub fn ip_addr_add_args(vip: &VipSpec) -> Vec<String> {
    vec![
        "addr".into(),
        "add".into(),
        vip.cidr(),
        "dev".into(),
        vip.interface.clone(),
    ]
}

/// Build the `ip addr del` argument vector for `vip`.
#[must_use]
pub fn ip_addr_del_args(vip: &VipSpec) -> Vec<String> {
    vec![
        "addr".into(),
        "del".into(),
        vip.cidr(),
        "dev".into(),
        vip.interface.clone(),
    ]
}

/// Build the `arping` gratuitous-announcement argument vector.
/// `-A` sends ARP replies (gratuitous), `-c` bounds the count,
/// `-I` selects the interface.
#[must_use]
pub fn arping_args(vip: &VipSpec, count: u8) -> Vec<String> {
    let addr = vip.address.to_string();
    vec![
        "-A".into(),
        "-c".into(),
        count.to_string(),
        "-I".into(),
        vip.interface.clone(),
        addr,
    ]
}

/// Production [`VipManager`] that shells out to `ip` (and,
/// best-effort, `arping`). Mirrors [`sng_fw`]'s `ShellNftables`.
#[derive(Clone, Debug)]
pub struct ShellVipManager {
    /// Path to the `ip` binary. Defaults to `"ip"` (PATH lookup).
    pub ip_binary: String,
    /// Path to the `arping` binary. Defaults to `"arping"`.
    pub arping_binary: String,
    /// Number of gratuitous ARP announcements on acquire.
    pub gratuitous_arp_count: u8,
}

impl Default for ShellVipManager {
    fn default() -> Self {
        Self {
            ip_binary: "ip".into(),
            arping_binary: "arping".into(),
            gratuitous_arp_count: DEFAULT_GRATUITOUS_ARP_COUNT,
        }
    }
}

impl ShellVipManager {
    /// Construct with default binary names.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `ip` with `args`. `tolerate_exists` maps the
    /// "address already assigned" / "cannot assign" exit into
    /// success so acquire / release are idempotent.
    async fn run_ip(&self, args: &[String], tolerate_exists: bool) -> HaResult<()> {
        let output = Command::new(&self.ip_binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| HaError::Vip(format!("spawn {}: {e}", self.ip_binary)))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lower = stderr.to_ascii_lowercase();
        if tolerate_exists
            && (lower.contains("file exists") || lower.contains("cannot assign requested address"))
        {
            // Idempotent no-op: the address was already in the
            // desired state.
            return Ok(());
        }
        Err(HaError::Vip(format!(
            "{} {} exited {}: {}",
            self.ip_binary,
            args.join(" "),
            output.status,
            stderr.trim()
        )))
    }

    /// Send the gratuitous ARP announcement. Best-effort: a
    /// failure (missing `arping`, no `CAP_NET_RAW`) is logged
    /// and swallowed because the `ip addr add` above already
    /// triggered a kernel gratuitous ARP.
    async fn announce(&self, vip: &VipSpec) {
        let args = arping_args(vip, self.gratuitous_arp_count);
        match Command::new(&self.arping_binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                tracing::debug!(target: "sng_ha::vip", vip = %vip.cidr(), "gratuitous ARP sent");
            }
            Ok(out) => {
                tracing::warn!(
                    target: "sng_ha::vip",
                    vip = %vip.cidr(),
                    status = %out.status,
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "gratuitous ARP failed (kernel already announced on addr add); continuing"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "sng_ha::vip",
                    vip = %vip.cidr(),
                    error = %e,
                    "arping unavailable (kernel already announced on addr add); continuing"
                );
            }
        }
    }
}

#[async_trait]
impl VipManager for ShellVipManager {
    async fn acquire(&self, vip: &VipSpec) -> HaResult<()> {
        vip.validate()?;
        self.run_ip(&ip_addr_add_args(vip), true).await?;
        self.announce(vip).await;
        tracing::info!(target: "sng_ha::vip", vip = %vip.cidr(), dev = %vip.interface, "VIP acquired");
        Ok(())
    }

    async fn release(&self, vip: &VipSpec) -> HaResult<()> {
        vip.validate()?;
        self.run_ip(&ip_addr_del_args(vip), true).await?;
        tracing::info!(target: "sng_ha::vip", vip = %vip.cidr(), dev = %vip.interface, "VIP released");
        Ok(())
    }
}

/// No-op manager for single-edge (HA-disabled) deployments. The
/// controller installs this so the role-change plumbing runs
/// unchanged while never touching the host's addresses.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopVipManager;

#[async_trait]
impl VipManager for NoopVipManager {
    async fn acquire(&self, _vip: &VipSpec) -> HaResult<()> {
        Ok(())
    }

    async fn release(&self, _vip: &VipSpec) -> HaResult<()> {
        Ok(())
    }
}

/// Test double that records the acquire / release calls so a
/// test can assert the controller drove VIP ownership correctly.
#[derive(Clone, Debug, Default)]
pub struct RecordingVipManager {
    events: std::sync::Arc<parking_lot::Mutex<Vec<VipEvent>>>,
}

/// One recorded VIP transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VipEvent {
    /// `acquire` was called for this spec.
    Acquired(VipSpec),
    /// `release` was called for this spec.
    Released(VipSpec),
}

impl RecordingVipManager {
    /// Empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the recorded events in call order.
    #[must_use]
    pub fn events(&self) -> Vec<VipEvent> {
        self.events.lock().clone()
    }
}

#[async_trait]
impl VipManager for RecordingVipManager {
    async fn acquire(&self, vip: &VipSpec) -> HaResult<()> {
        vip.validate()?;
        self.events.lock().push(VipEvent::Acquired(vip.clone()));
        Ok(())
    }

    async fn release(&self, vip: &VipSpec) -> HaResult<()> {
        vip.validate()?;
        self.events.lock().push(VipEvent::Released(vip.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::net::Ipv4Addr;

    fn vip() -> VipSpec {
        VipSpec::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24, "eth0")
    }

    #[test]
    fn cidr_formats_address_and_prefix() {
        assert_eq!(vip().cidr(), "192.168.1.10/24");
    }

    #[test]
    fn validate_rejects_empty_interface_and_bad_prefix() {
        assert!(
            VipSpec::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 24, "  ")
                .validate()
                .is_err()
        );
        assert!(
            VipSpec::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33, "eth0")
                .validate()
                .is_err()
        );
        assert!(vip().validate().is_ok());
    }

    #[test]
    fn ip_arg_vectors_match_expected_surface() {
        assert_eq!(
            ip_addr_add_args(&vip()),
            vec!["addr", "add", "192.168.1.10/24", "dev", "eth0"]
        );
        assert_eq!(
            ip_addr_del_args(&vip()),
            vec!["addr", "del", "192.168.1.10/24", "dev", "eth0"]
        );
        assert_eq!(
            arping_args(&vip(), 3),
            vec!["-A", "-c", "3", "-I", "eth0", "192.168.1.10"]
        );
    }

    #[tokio::test]
    async fn noop_manager_is_inert() {
        let m = NoopVipManager;
        assert!(m.acquire(&vip()).await.is_ok());
        assert!(m.release(&vip()).await.is_ok());
    }

    #[tokio::test]
    async fn recording_manager_tracks_calls() {
        let m = RecordingVipManager::new();
        m.acquire(&vip()).await.expect("acquire");
        m.release(&vip()).await.expect("release");
        assert_eq!(
            m.events(),
            vec![VipEvent::Acquired(vip()), VipEvent::Released(vip())]
        );
    }
}
