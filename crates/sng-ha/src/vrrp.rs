//! VRRP-class active/passive election between two `sng-edge`
//! instances sharing an L2 segment.
//!
//! This is a deliberately *simplified* subset of RFC 5798: a
//! single virtual router, two participants (one configured with
//! a higher priority than the other), and the three-state
//! machine the RFC defines — `Initialize -> {Backup, Master}`.
//! The pieces of the RFC that matter for a two-node edge HA
//! pair are implemented faithfully:
//!
//! * **Priority semantics.** Priority 255 is the address owner
//!   (immediate Master); priority 0 is the reserved "I am
//!   releasing the role" signal a Master emits when it
//!   voluntarily steps down (see [`crate::health`]). Operator
//!   priorities live in `1..=254`.
//! * **Master-down interval.** A Backup promotes itself when
//!   `3 * advertisement_interval + skew_time` elapses without
//!   hearing a Master, where `skew_time = (256 - priority) /
//!   256 * advertisement_interval` biases the higher-priority
//!   node to win a simultaneous-start race (RFC 5798 §6.1).
//! * **Preempt mode.** When enabled (the default), a Backup
//!   that hears a *lower*-priority Master keeps its
//!   master-down timer running so it takes the role back; when
//!   disabled, any live Master holds the role until it dies.
//!
//! The state machine itself ([`VrrpInstance`]) is a pure,
//! synchronous decision core with no I/O — every transition is
//! driven by one of three events ([`VrrpEvent`]) and returns a
//! [`Transition`] the async run loop in [`crate::HaController`]
//! acts on. That split keeps the election logic exhaustively
//! unit-testable without a socket, while the multicast wire
//! lives behind the [`AdvertisementChannel`] trait so a test
//! can drive the same loop over an in-memory channel.

use crate::error::{HaError, HaResult};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// Standard VRRP IPv4 multicast group (RFC 5798 §5.1.1.2).
pub const VRRP_MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

/// UDP port the simplified advertisement frames are exchanged
/// on. Real VRRP rides directly on IP protocol 112; sending raw
/// IP-protocol packets needs a raw socket (and `CAP_NET_RAW` +
/// an `unsafe` libc shim), so this implementation rides the
/// same multicast *group* over a UDP port instead. The port is
/// outside the IANA well-known range and configurable on
/// [`MulticastChannel::bind`] for deployments that need to
/// avoid a collision.
pub const VRRP_UDP_PORT: u16 = 1112;

/// Default advertisement cadence (RFC 5798 default is 1s).
pub const DEFAULT_ADVERTISEMENT_INTERVAL: Duration = Duration::from_secs(1);

/// Reserved priority a Master emits to announce it is giving up
/// the role immediately (RFC 5798 §5.2.4). Receiving it lets a
/// Backup skip most of the master-down interval.
pub const PRIORITY_RELEASE: u8 = 0;

/// Reserved priority of the VIP address owner — an owner is
/// always Master while it is up.
pub const PRIORITY_OWNER: u8 = 255;

/// Magic prefix on every advertisement frame so a stray packet
/// on the UDP port is rejected before the fixed fields are
/// parsed.
const FRAME_MAGIC: [u8; 2] = *b"VR";

/// Wire length of an advertisement frame: 2 magic + 1 version +
/// 1 vrid + 1 priority + 2 advertisement-interval-centiseconds.
const FRAME_LEN: usize = 7;

/// Protocol version this implementation speaks.
const FRAME_VERSION: u8 = 1;

/// The three VRRP states. `Initialize` is the boot state before
/// the first timer tick; the machine immediately leaves it for
/// `Backup` (or `Master`, for the address owner) on
/// [`VrrpInstance::start`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VrrpState {
    /// Pre-start state. No advertisements sent, no role held.
    Initialize,
    /// Listening for a Master; will promote on master-down.
    Backup,
    /// Owns the VIP and sends periodic advertisements.
    Master,
}

/// A role change a [`Transition`] asks the controller to enact.
/// The controller maps `Promoted` onto VIP acquisition + a
/// full-state pull, and `Demoted` onto VIP release.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RoleChange {
    /// Backup -> Master. Acquire the VIP, send a gratuitous ARP.
    Promoted,
    /// Master -> Backup. Release the VIP.
    Demoted,
}

/// What a [`Transition`] asks the controller to do with the
/// Backup master-down timer.
///
/// The state machine owns this decision so the controller never
/// has to second-guess it out-of-band — the timer behaviour and
/// the role decision always come from the same `on_advertisement`
/// evaluation, which is what makes preempt mode correct.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum MasterDown {
    /// Leave the master-down timer exactly as it is. Either the
    /// event has no bearing on it (a Master's own advertisement
    /// tick, a foreign-VRID packet, anything received while
    /// Master) or a Backup is deliberately letting the current
    /// deadline run out so it preempts a lower-priority Master.
    #[default]
    Leave,
    /// A live, acceptable Master was heard — re-arm to the full
    /// master-down interval.
    ResetFull,
    /// The Master announced it is releasing the role — re-arm to
    /// the short skew time so this Backup promotes promptly
    /// instead of waiting out the whole interval.
    ResetSkew,
}

/// Outcome of feeding one [`VrrpEvent`] to a [`VrrpInstance`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Transition {
    /// Set when the state changed in a way the controller must
    /// act on (VIP acquire / release).
    pub role_change: Option<RoleChange>,
    /// Set when the instance should emit an advertisement now
    /// (a Master's periodic tick, or an immediate re-assert
    /// after hearing a release).
    pub send_advertisement: bool,
    /// What the controller should do with the master-down timer.
    pub master_down: MasterDown,
}

impl Transition {
    const NONE: Self = Self {
        role_change: None,
        send_advertisement: false,
        master_down: MasterDown::Leave,
    };

    const fn send() -> Self {
        Self {
            role_change: None,
            send_advertisement: true,
            master_down: MasterDown::Leave,
        }
    }

    const fn promote() -> Self {
        Self {
            role_change: Some(RoleChange::Promoted),
            send_advertisement: true,
            master_down: MasterDown::Leave,
        }
    }

    const fn demote() -> Self {
        Self {
            role_change: Some(RoleChange::Demoted),
            send_advertisement: false,
            master_down: MasterDown::Leave,
        }
    }

    /// Override the master-down directive on an otherwise-built
    /// transition.
    #[must_use]
    fn with_master_down(mut self, md: MasterDown) -> Self {
        self.master_down = md;
        self
    }
}

/// Events that drive the state machine. The async run loop
/// translates wall-clock timers and inbound packets into these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VrrpEvent {
    /// The advertisement timer fired (Master only — Backup
    /// ignores it).
    AdvertisementTimer,
    /// The master-down timer fired (Backup only — Master
    /// ignores it).
    MasterDownTimer,
    /// An advertisement was received from the peer.
    Advertisement(VrrpAdvertisement),
}

/// A decoded advertisement. `source` is the peer's address, used
/// only to break a priority tie deterministically (higher IP
/// wins, per RFC 5798 §6.4.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VrrpAdvertisement {
    /// Virtual router id the advertisement is for.
    pub virtual_router_id: u8,
    /// Sender's current priority.
    pub priority: u8,
    /// Sender's advertised interval.
    pub advertisement_interval: Duration,
    /// Sender's address (tie-break only).
    pub source: IpAddr,
}

impl VrrpAdvertisement {
    /// Encode to the fixed-width wire frame.
    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        // Advertisement interval is carried in centiseconds as a
        // big-endian u16 — RFC 5798 uses centiseconds for the
        // Max-Adver-Int field. Saturate so a pathological
        // multi-hour interval cannot wrap the u16.
        let centis =
            u16::try_from(self.advertisement_interval.as_millis() / 10).unwrap_or(u16::MAX);
        let cb = centis.to_be_bytes();
        [
            FRAME_MAGIC[0],
            FRAME_MAGIC[1],
            FRAME_VERSION,
            self.virtual_router_id,
            self.priority,
            cb[0],
            cb[1],
        ]
    }

    /// Decode a frame received from `source`. The transport
    /// supplies the peer address; it is not carried on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::Decode`] if the frame is too short,
    /// carries the wrong magic, or announces an unknown version.
    pub fn decode(bytes: &[u8], source: IpAddr) -> HaResult<Self> {
        if bytes.len() < FRAME_LEN {
            return Err(HaError::Decode(format!(
                "advertisement frame too short: {} < {FRAME_LEN}",
                bytes.len()
            )));
        }
        if bytes[0..2] != FRAME_MAGIC {
            return Err(HaError::Decode("bad advertisement magic".into()));
        }
        if bytes[2] != FRAME_VERSION {
            return Err(HaError::Decode(format!(
                "unsupported advertisement version {}",
                bytes[2]
            )));
        }
        let centis = u16::from_be_bytes([bytes[5], bytes[6]]);
        Ok(Self {
            virtual_router_id: bytes[3],
            priority: bytes[4],
            advertisement_interval: Duration::from_millis(u64::from(centis) * 10),
            source,
        })
    }
}

/// Static configuration of a VRRP participant.
#[derive(Clone, Debug)]
pub struct VrrpConfig {
    /// Virtual router id — both peers in a pair share this.
    pub virtual_router_id: u8,
    /// Configured priority in `1..=255`. Higher wins.
    pub priority: u8,
    /// Advertisement cadence (Master) and the unit the
    /// master-down interval is derived from (Backup).
    pub advertisement_interval: Duration,
    /// When `true`, a higher-priority node takes the role back
    /// from a lower-priority Master. When `false`, whoever is
    /// Master keeps it until it dies.
    pub preempt_mode: bool,
}

impl Default for VrrpConfig {
    fn default() -> Self {
        Self {
            virtual_router_id: 1,
            priority: 100,
            advertisement_interval: DEFAULT_ADVERTISEMENT_INTERVAL,
            preempt_mode: true,
        }
    }
}

impl VrrpConfig {
    /// Validate the operator-supplied fields.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::InvalidConfig`] for a zero priority
    /// (reserved for the release signal), a zero
    /// advertisement interval, or a zero virtual router id.
    pub fn validate(&self) -> HaResult<()> {
        if self.virtual_router_id == 0 {
            return Err(HaError::InvalidConfig(
                "virtual_router_id must be in 1..=255".into(),
            ));
        }
        if self.priority == PRIORITY_RELEASE {
            return Err(HaError::InvalidConfig(
                "priority 0 is reserved for the release signal; use 1..=255".into(),
            ));
        }
        if self.advertisement_interval.is_zero() {
            return Err(HaError::InvalidConfig(
                "advertisement_interval must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// The pure election state machine for one virtual router.
///
/// Holds no sockets and does no I/O: [`Self::handle`] is a
/// synchronous transition function the async run loop calls.
/// `effective_priority` tracks the *current* priority, which
/// drops to [`PRIORITY_RELEASE`] when [`Self::set_released`] is
/// invoked by a failing health probe.
#[derive(Clone, Debug)]
pub struct VrrpInstance {
    config: VrrpConfig,
    state: VrrpState,
    effective_priority: u8,
    /// This node's own address. Stamped onto outbound
    /// advertisements and used as the loser's side of the
    /// equal-priority tie-break (RFC 5798 §6.4.3: higher source
    /// address wins). Kept on the instance — not [`VrrpConfig`] —
    /// so the config stays a pure, shareable description while
    /// the per-node identity lives with the running machine.
    local_addr: IpAddr,
}

impl VrrpInstance {
    /// Construct in the `Initialize` state.
    ///
    /// `local_addr` is this node's own address; it is stamped onto
    /// outbound advertisements and is the tie-breaker when the peer
    /// advertises an equal priority.
    ///
    /// # Errors
    ///
    /// Propagates [`VrrpConfig::validate`].
    pub fn new(config: VrrpConfig, local_addr: IpAddr) -> HaResult<Self> {
        config.validate()?;
        let effective_priority = config.priority;
        Ok(Self {
            config,
            state: VrrpState::Initialize,
            effective_priority,
            local_addr,
        })
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> VrrpState {
        self.state
    }

    /// Current effective priority (post any health demotion).
    #[must_use]
    pub fn effective_priority(&self) -> u8 {
        self.effective_priority
    }

    /// Configured (un-demoted) priority.
    #[must_use]
    pub fn configured_priority(&self) -> u8 {
        self.config.priority
    }

    /// Virtual router id.
    #[must_use]
    pub fn virtual_router_id(&self) -> u8 {
        self.config.virtual_router_id
    }

    /// Advertisement cadence.
    #[must_use]
    pub fn advertisement_interval(&self) -> Duration {
        self.config.advertisement_interval
    }

    /// Skew time — biases the higher-priority node to win a
    /// simultaneous start (RFC 5798 §6.1).
    #[must_use]
    pub fn skew_time(&self) -> Duration {
        let p = u32::from(self.effective_priority);
        // (256 - priority) / 256 * interval
        self.config
            .advertisement_interval
            .mul_f64(f64::from(256 - p) / 256.0)
    }

    /// Master-down interval: `3 * interval + skew`. A Backup
    /// promotes itself when this elapses without a Master
    /// advertisement.
    #[must_use]
    pub fn master_down_interval(&self) -> Duration {
        self.config
            .advertisement_interval
            .saturating_mul(3)
            .saturating_add(self.skew_time())
    }

    /// This node's own address (advertisement source / tie-break).
    #[must_use]
    pub fn local_addr(&self) -> IpAddr {
        self.local_addr
    }

    /// Build the advertisement this instance would send right
    /// now, stamped with its own [`local_addr`](Self::local_addr).
    #[must_use]
    pub fn advertisement(&self) -> VrrpAdvertisement {
        VrrpAdvertisement {
            virtual_router_id: self.config.virtual_router_id,
            priority: self.effective_priority,
            advertisement_interval: self.config.advertisement_interval,
            source: self.local_addr,
        }
    }

    /// Leave `Initialize`. The address owner (priority 255)
    /// becomes Master immediately; everyone else starts as
    /// Backup and waits out the master-down interval.
    pub fn start(&mut self) -> Transition {
        if self.state != VrrpState::Initialize {
            return Transition::NONE;
        }
        if self.config.priority == PRIORITY_OWNER {
            self.state = VrrpState::Master;
            Transition::promote()
        } else {
            self.state = VrrpState::Backup;
            Transition::NONE
        }
    }

    /// Voluntarily release the Master role: priority drops to 0.
    /// Called when a mandatory health probe fails. If currently
    /// Master, the caller should also emit the priority-0
    /// advertisement returned via [`Transition::send_advertisement`]
    /// so the peer promotes promptly.
    pub fn set_released(&mut self) -> Transition {
        self.effective_priority = PRIORITY_RELEASE;
        if self.state == VrrpState::Master {
            // Stay Master until the peer takes over (it will, on
            // the priority-0 advertisement), but stop asserting a
            // real priority. Emit the release advertisement now.
            Transition::send()
        } else {
            Transition::NONE
        }
    }

    /// Restore the configured priority after health recovers.
    /// Does not itself change state — preempt logic on the next
    /// advertisement handles re-election.
    pub fn clear_released(&mut self) {
        self.effective_priority = self.config.priority;
    }

    /// Feed one event to the machine and get the resulting
    /// [`Transition`].
    pub fn handle(&mut self, event: &VrrpEvent) -> Transition {
        match (self.state, event) {
            (VrrpState::Master, VrrpEvent::AdvertisementTimer) => Transition::send(),
            (VrrpState::Backup, VrrpEvent::MasterDownTimer) => {
                self.state = VrrpState::Master;
                Transition::promote()
            }
            (_, VrrpEvent::Advertisement(adv)) => self.on_advertisement(*adv),
            // Master ignores its own master-down timer; Backup
            // ignores the advertisement timer; Initialize ignores
            // every timer until `start` runs.
            _ => Transition::NONE,
        }
    }

    /// Core RFC 5798 §6.4 receive logic, collapsed to the
    /// two-node case.
    fn on_advertisement(&mut self, adv: VrrpAdvertisement) -> Transition {
        if adv.virtual_router_id != self.config.virtual_router_id {
            // Not our virtual router — ignore entirely.
            return Transition::NONE;
        }
        match self.state {
            VrrpState::Initialize => Transition::NONE,
            VrrpState::Master => {
                if self.peer_outranks(&adv) {
                    // A higher-priority (or equal-priority,
                    // higher-address) Master exists: step down. As a
                    // Backup the controller re-arms the master-down
                    // timer off this role change.
                    self.state = VrrpState::Backup;
                    Transition::demote()
                } else if adv.priority == PRIORITY_RELEASE {
                    // Peer is releasing; re-assert ourselves now.
                    Transition::send()
                } else {
                    // Lower-priority (or equal, lower-address)
                    // chatter — hold the role, timer stays disabled.
                    Transition::NONE
                }
            }
            VrrpState::Backup => {
                if adv.priority == PRIORITY_RELEASE {
                    // Master is going away — promote after the short
                    // skew instead of the whole master-down interval.
                    Transition::NONE.with_master_down(MasterDown::ResetSkew)
                } else if self.config.preempt_mode && adv.priority < self.effective_priority {
                    // We strictly outrank this Master and preempt is
                    // on: leave the master-down timer running so it
                    // expires and we take the role back. (Equal
                    // priority is NOT preempted — RFC 5798 §6.4.2
                    // only preempts a *lower*-priority Master.)
                    Transition::NONE
                } else {
                    // A Master we accept — stay Backup and re-arm the
                    // full master-down interval.
                    Transition::NONE.with_master_down(MasterDown::ResetFull)
                }
            }
        }
    }

    /// True when `adv` should beat us for the Master role:
    /// strictly higher priority, or equal priority with a higher
    /// source address (deterministic tie-break, RFC 5798 §6.4.3).
    /// The address comparison prevents two equal-priority Masters
    /// (the out-of-the-box 100/100 case) from holding the VIP
    /// simultaneously after a healed partition.
    fn peer_outranks(&self, adv: &VrrpAdvertisement) -> bool {
        adv.priority > self.effective_priority
            || (adv.priority == self.effective_priority && adv.source > self.local_addr)
    }
}

/// Transport over which advertisements are exchanged. The
/// production implementation ([`MulticastChannel`]) joins
/// `224.0.0.18`; tests use an in-memory double so the run loop
/// can be exercised without a multicast-capable host.
#[async_trait]
pub trait AdvertisementChannel: Send + Sync + std::fmt::Debug {
    /// Multicast an advertisement frame to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::Socket`] if the send fails.
    async fn send(&self, frame: &[u8]) -> HaResult<()>;

    /// Await the next advertisement. Returns the decoded
    /// advertisement plus the source address used for tie-break.
    ///
    /// # Errors
    ///
    /// Returns [`HaError::Socket`] on a receive error or
    /// [`HaError::Decode`] on a malformed frame.
    async fn recv(&self) -> HaResult<VrrpAdvertisement>;
}

/// Production multicast transport. Built from a `socket2` socket
/// so the multicast TTL and group membership can be set before
/// the socket is handed to tokio.
#[derive(Debug)]
pub struct MulticastChannel {
    socket: tokio::net::UdpSocket,
    group: SocketAddrV4,
}

impl MulticastChannel {
    /// Bind the VRRP multicast socket on `interface_addr`, join
    /// [`VRRP_MULTICAST_GROUP`], and set the multicast TTL to
    /// 255 (RFC 5798 §5.1.1.3 — advertisements must not be
    /// routed off-segment).
    ///
    /// # Errors
    ///
    /// Returns [`HaError::Socket`] if any socket option, the
    /// bind, or the group join fails.
    pub fn bind(interface_addr: Ipv4Addr, port: u16) -> HaResult<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| HaError::Socket(format!("create: {e}")))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| HaError::Socket(format!("set_reuse_address: {e}")))?;
        // Bind to the wildcard on the VRRP port so the multicast
        // group's traffic is delivered; the membership join below
        // scopes which group we receive.
        let bind_addr: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        socket
            .bind(&bind_addr.into())
            .map_err(|e| HaError::Socket(format!("bind {bind_addr}: {e}")))?;
        socket
            .join_multicast_v4(&VRRP_MULTICAST_GROUP, &interface_addr)
            .map_err(|e| HaError::Socket(format!("join_multicast_v4: {e}")))?;
        socket
            .set_multicast_ttl_v4(255)
            .map_err(|e| HaError::Socket(format!("set_multicast_ttl_v4: {e}")))?;
        socket
            .set_multicast_loop_v4(false)
            .map_err(|e| HaError::Socket(format!("set_multicast_loop_v4: {e}")))?;
        socket
            .set_multicast_if_v4(&interface_addr)
            .map_err(|e| HaError::Socket(format!("set_multicast_if_v4: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| HaError::Socket(format!("set_nonblocking: {e}")))?;
        let std_socket: std::net::UdpSocket = socket.into();
        let socket = tokio::net::UdpSocket::from_std(std_socket)
            .map_err(|e| HaError::Socket(format!("from_std: {e}")))?;
        Ok(Self {
            socket,
            group: SocketAddrV4::new(VRRP_MULTICAST_GROUP, port),
        })
    }
}

#[async_trait]
impl AdvertisementChannel for MulticastChannel {
    async fn send(&self, frame: &[u8]) -> HaResult<()> {
        self.socket
            .send_to(frame, self.group)
            .await
            .map(|_| ())
            .map_err(|e| HaError::Socket(format!("send_to {}: {e}", self.group)))
    }

    async fn recv(&self) -> HaResult<VrrpAdvertisement> {
        let mut buf = [0u8; 64];
        let (n, peer) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| HaError::Socket(format!("recv_from: {e}")))?;
        VrrpAdvertisement::decode(&buf[..n], peer.ip())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn cfg(priority: u8, preempt: bool) -> VrrpConfig {
        VrrpConfig {
            virtual_router_id: 7,
            priority,
            advertisement_interval: Duration::from_secs(1),
            preempt_mode: preempt,
        }
    }

    /// This node's address in the tests. Lower than [`adv`]'s
    /// source (`10.0.0.2`), so the peer wins an equal-priority
    /// tie-break by default.
    const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    fn inst(priority: u8, preempt: bool) -> VrrpInstance {
        VrrpInstance::new(cfg(priority, preempt), LOCAL).expect("new")
    }

    fn adv(vrid: u8, priority: u8) -> VrrpAdvertisement {
        adv_from(vrid, priority, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    }

    fn adv_from(vrid: u8, priority: u8, source: IpAddr) -> VrrpAdvertisement {
        VrrpAdvertisement {
            virtual_router_id: vrid,
            priority,
            advertisement_interval: Duration::from_secs(1),
            source,
        }
    }

    #[test]
    fn config_validation_rejects_reserved_and_zero_values() {
        assert!(cfg(0, true).validate().is_err());
        assert!(
            VrrpConfig {
                virtual_router_id: 0,
                ..cfg(100, true)
            }
            .validate()
            .is_err()
        );
        assert!(
            VrrpConfig {
                advertisement_interval: Duration::ZERO,
                ..cfg(100, true)
            }
            .validate()
            .is_err()
        );
        assert!(cfg(100, true).validate().is_ok());
    }

    #[test]
    fn advertisement_round_trips_through_wire() {
        let a = adv(7, 200);
        let frame = a.encode();
        let decoded = VrrpAdvertisement::decode(&frame, a.source).expect("decode");
        assert_eq!(decoded, a);
    }

    #[test]
    fn decode_rejects_short_bad_magic_and_version() {
        let src = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(VrrpAdvertisement::decode(&[0u8; 3], src).is_err());
        let mut frame = adv(1, 1).encode();
        frame[0] = b'X';
        assert!(VrrpAdvertisement::decode(&frame, src).is_err());
        let mut frame = adv(1, 1).encode();
        frame[2] = 9;
        assert!(VrrpAdvertisement::decode(&frame, src).is_err());
    }

    #[test]
    fn owner_becomes_master_immediately() {
        let mut vi = inst(PRIORITY_OWNER, true);
        let t = vi.start();
        assert_eq!(vi.state(), VrrpState::Master);
        assert_eq!(t.role_change, Some(RoleChange::Promoted));
        assert!(t.send_advertisement);
    }

    #[test]
    fn non_owner_starts_backup() {
        let mut vi = inst(100, true);
        let t = vi.start();
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t, Transition::NONE);
    }

    #[test]
    fn backup_promotes_on_master_down() {
        let mut vi = inst(100, true);
        vi.start();
        let t = vi.handle(&VrrpEvent::MasterDownTimer);
        assert_eq!(vi.state(), VrrpState::Master);
        assert_eq!(t.role_change, Some(RoleChange::Promoted));
    }

    #[test]
    fn master_steps_down_for_higher_priority_peer() {
        let mut vi = inst(100, true);
        vi.start();
        vi.handle(&VrrpEvent::MasterDownTimer); // -> Master
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, 200)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t.role_change, Some(RoleChange::Demoted));
    }

    #[test]
    fn master_holds_against_lower_priority_peer() {
        let mut vi = inst(200, true);
        vi.start();
        vi.handle(&VrrpEvent::MasterDownTimer); // -> Master
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, 100)));
        assert_eq!(vi.state(), VrrpState::Master);
        assert_eq!(t, Transition::NONE);
    }

    #[test]
    fn master_reasserts_on_peer_release() {
        let mut vi = inst(200, true);
        vi.start();
        vi.handle(&VrrpEvent::MasterDownTimer);
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, PRIORITY_RELEASE)));
        assert_eq!(vi.state(), VrrpState::Master);
        assert!(t.send_advertisement);
    }

    #[test]
    fn advertisement_for_other_vrid_is_ignored() {
        let mut vi = inst(100, true);
        vi.start();
        vi.handle(&VrrpEvent::MasterDownTimer); // -> Master
        let t = vi.handle(&VrrpEvent::Advertisement(adv(99, 255)));
        assert_eq!(vi.state(), VrrpState::Master);
        assert_eq!(t, Transition::NONE);
    }

    #[test]
    fn release_drops_priority_and_emits_when_master() {
        let mut vi = inst(200, true);
        vi.start();
        vi.handle(&VrrpEvent::MasterDownTimer); // -> Master
        let t = vi.set_released();
        assert_eq!(vi.effective_priority(), PRIORITY_RELEASE);
        assert!(t.send_advertisement);
        // After release, a peer with any real priority outranks us.
        let t2 = vi.handle(&VrrpEvent::Advertisement(adv(7, 1)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t2.role_change, Some(RoleChange::Demoted));
    }

    #[test]
    fn clear_released_restores_priority() {
        let mut vi = inst(150, true);
        vi.set_released();
        assert_eq!(vi.effective_priority(), PRIORITY_RELEASE);
        vi.clear_released();
        assert_eq!(vi.effective_priority(), 150);
    }

    #[test]
    fn backup_resets_full_master_down_for_acceptable_master() {
        // A Backup that hears a higher-priority Master accepts it
        // and re-arms the full master-down interval.
        let mut vi = inst(100, true);
        vi.start(); // -> Backup
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, 150)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t.master_down, MasterDown::ResetFull);
        assert!(t.role_change.is_none());
    }

    #[test]
    fn backup_preempts_lower_priority_master_by_leaving_timer() {
        // BUG-0001 regression: a higher-priority Backup with preempt
        // on must NOT reset its master-down timer when it hears a
        // lower-priority Master — otherwise it can never take over.
        let mut vi = inst(200, true);
        vi.start(); // -> Backup
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, 100)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(
            t.master_down,
            MasterDown::Leave,
            "preempting Backup must leave its master-down timer running"
        );
    }

    #[test]
    fn backup_without_preempt_accepts_lower_priority_master() {
        // With preempt off, even a higher-priority Backup yields to a
        // live lower-priority Master and re-arms the full interval.
        let mut vi = inst(200, false);
        vi.start(); // -> Backup
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, 100)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t.master_down, MasterDown::ResetFull);
    }

    #[test]
    fn backup_equal_priority_master_is_accepted_not_preempted() {
        // Equal priority is never preempted (RFC 5798 §6.4.2 only
        // preempts a strictly lower-priority Master), so two
        // default-100 peers do not both try to be Master.
        let mut vi = inst(100, true);
        vi.start(); // -> Backup
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, 100)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t.master_down, MasterDown::ResetFull);
    }

    #[test]
    fn backup_arms_skew_on_peer_release() {
        let mut vi = inst(100, true);
        vi.start(); // -> Backup
        let t = vi.handle(&VrrpEvent::Advertisement(adv(7, PRIORITY_RELEASE)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t.master_down, MasterDown::ResetSkew);
    }

    #[test]
    fn backup_leaves_timer_for_foreign_vrid() {
        // A packet for another virtual router must not touch our
        // master-down timer.
        let mut vi = inst(100, true);
        vi.start(); // -> Backup
        let t = vi.handle(&VrrpEvent::Advertisement(adv(99, 200)));
        assert_eq!(vi.state(), VrrpState::Backup);
        assert_eq!(t.master_down, MasterDown::Leave);
        assert_eq!(t, Transition::NONE);
    }

    #[test]
    fn equal_priority_master_steps_down_for_higher_source_address() {
        // BUG-0002 regression: two equal-priority Masters must not
        // split-brain. The one with the lower address steps down.
        let mut low =
            VrrpInstance::new(cfg(100, true), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).expect("new");
        low.start();
        low.handle(&VrrpEvent::MasterDownTimer); // -> Master
        let peer = adv_from(7, 100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
        let t = low.handle(&VrrpEvent::Advertisement(peer));
        assert_eq!(low.state(), VrrpState::Backup);
        assert_eq!(t.role_change, Some(RoleChange::Demoted));
    }

    #[test]
    fn equal_priority_master_holds_against_lower_source_address() {
        // The mirror image: the higher-address node keeps the role
        // when it hears an equal-priority, lower-address peer.
        let mut high =
            VrrpInstance::new(cfg(100, true), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))).expect("new");
        high.start();
        high.handle(&VrrpEvent::MasterDownTimer); // -> Master
        let peer = adv_from(7, 100, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let t = high.handle(&VrrpEvent::Advertisement(peer));
        assert_eq!(high.state(), VrrpState::Master);
        assert_eq!(t, Transition::NONE);
    }

    #[test]
    fn master_down_interval_uses_three_intervals_plus_skew() {
        // skew = (256 - priority)/256 * interval; master-down =
        // 3 * interval + skew (RFC 5798 §6.1).
        let low = inst(128, true);
        // skew = (256-128)/256 * 1s = 0.5s => 3.5s
        assert_eq!(low.skew_time(), Duration::from_millis(500));
        assert_eq!(low.master_down_interval(), Duration::from_millis(3500));

        // A higher priority yields a shorter skew, so the
        // higher-priority node always has the earlier deadline and
        // wins a simultaneous start.
        let high = inst(200, true);
        assert!(high.master_down_interval() < low.master_down_interval());
        assert_eq!(
            high.master_down_interval(),
            high.advertisement_interval().saturating_mul(3) + high.skew_time()
        );
    }
}
