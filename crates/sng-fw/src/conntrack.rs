//! Bounded connection-tracking table.
//!
//! [`ConnTable`] is the firewall's per-flow state store. It
//! holds one [`ConnTrackEntry`] per `FlowKey` (forward
//! direction) and a reverse-direction index so a
//! server-to-client packet matches the existing flow without
//! the caller having to know which direction it's looking
//! at.
//!
//! Capacity is bounded — when the table fills, the oldest
//! entry (smallest `last_seen_ms`) is evicted to make room.
//! The eviction policy keeps long-running flows in the table
//! at the expense of stale short-lived ones, which matches
//! the operational profile: a saturated edge VM is almost
//! always one with too many concurrent short flows (port
//! scans, NAT-translation tables, DNS lookups), and the
//! flows we actually care about (RDP, SSH, persistent TLS)
//! are the ones with high `last_seen_ms`.
//!
//! Idle eviction: [`ConnTable::sweep_idle`] drops any entry
//! whose `last_seen_ms` is more than the protocol-specific
//! idle timeout in the past. TCP-established flows keep the
//! conntrack default (10 minutes); UDP flows use a shorter
//! 60s default; TCP flows in `Closing` use 5s; flows in
//! `Closed` are dropped on the very next sweep.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::Duration;

use crate::error::FwError;
use crate::flow::{ConnState, FlowDirection, FlowKey, FlowState, IpProtocol};

/// Per-(flow-key) bookkeeping the conntrack table holds.
/// The forward key is stored in [`Self::flow_key`]; the
/// reverse direction has a pointer back into the forward
/// entry via the reverse-index map (managed by [`ConnTable`]
/// internally).
#[derive(Clone, Debug)]
pub struct ConnTrackEntry {
    /// Canonical (originator-side) 5-tuple.
    pub flow_key: FlowKey,
    /// Per-flow state (counters, conn state, app id, …).
    pub state: FlowState,
}

impl ConnTrackEntry {
    /// Helper used by the service to pull both key and state
    /// out of the entry when emitting a `FlowEvent`.
    #[must_use]
    pub fn snapshot(&self) -> (FlowKey, FlowState) {
        (self.flow_key, self.state.clone())
    }
}

/// Configuration for the conntrack table.
#[derive(Clone, Debug)]
pub struct ConnTableConfig {
    /// Maximum number of entries. Defaults to 131_072 —
    /// 128k, sized for a busy edge VM. Lower this for
    /// memory-constrained endpoints.
    pub max_entries: usize,
    /// Idle timeout for TCP flows in the `Established`
    /// state. Default 10 minutes, matching Linux netfilter.
    pub tcp_established_idle: Duration,
    /// Idle timeout for TCP flows in the `Closing` state.
    /// Defaults to 5 seconds — long enough to capture the
    /// final FIN+ACK, short enough not to retain dead
    /// connections.
    pub tcp_closing_idle: Duration,
    /// Idle timeout for UDP / ICMP / other stateless
    /// flows. Default 60 seconds — short, because the
    /// firewall has no protocol-level signal that the flow
    /// is over.
    pub stateless_idle: Duration,
}

impl Default for ConnTableConfig {
    fn default() -> Self {
        Self {
            max_entries: 131_072,
            tcp_established_idle: Duration::from_secs(600),
            tcp_closing_idle: Duration::from_secs(5),
            stateless_idle: Duration::from_secs(60),
        }
    }
}

impl ConnTableConfig {
    /// The idle timeout for a flow with the given protocol +
    /// conn state. The conntrack sweeper compares
    /// `now - entry.last_seen_ms` against this value.
    #[must_use]
    pub fn idle_for(&self, proto: IpProtocol, state: ConnState) -> Duration {
        match (proto, state) {
            (IpProtocol::Tcp, ConnState::Established) => self.tcp_established_idle,
            (IpProtocol::Tcp, ConnState::Closing) => self.tcp_closing_idle,
            // TCP half-open and Closed both get the
            // closing-idle timeout — Closed is removed on
            // the very next sweep regardless, but a stricter
            // bound for half-open prevents SYN-flood
            // exhaustion.
            (IpProtocol::Tcp, ConnState::SynSent | ConnState::SynReceived | ConnState::Closed) => {
                self.tcp_closing_idle
            }
            _ => self.stateless_idle,
        }
    }
}

/// The bounded LRU-by-`last_seen` connection table.
#[derive(Debug)]
pub struct ConnTable {
    config: ConnTableConfig,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Forward-direction map: originator's 5-tuple → entry.
    forward: HashMap<FlowKey, ConnTrackEntry>,
    /// Reverse-direction index: reverse 5-tuple → originator
    /// 5-tuple. Lets a server-to-client packet find the
    /// forward entry without scanning the table.
    reverse: HashMap<FlowKey, FlowKey>,
}

/// Result of [`ConnTable::lookup_or_create`] — tells the
/// caller whether a new entry was minted (so it needs to go
/// through policy evaluation) or an existing one was reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupOutcome {
    /// Flow is brand new; the caller must evaluate policy
    /// and may want to call [`ConnTable::update_app_id`]
    /// once the app id is resolved. `evicted_for_capacity`
    /// reports the number of LRU evictions that ran inside
    /// [`ConnTable::lookup_or_create`] to free a slot for
    /// this new entry — non-zero values indicate the table
    /// is sized too small for the offered load. The caller
    /// (typically [`crate::service::FwService`]) folds this
    /// into [`crate::stats::FwStats::record_flow_evicted_capacity`].
    Created {
        /// Count of entries evicted from the table to free a
        /// slot for the new flow. Zero on the common path.
        evicted_for_capacity: u32,
    },
    /// Flow already existed in the forward direction.
    ExistingForward,
    /// Flow already existed in the reverse direction (the
    /// packet is a server-to-client reply). The caller
    /// should credit bytes to the responder counter and
    /// reuse the established verdict.
    ExistingReverse,
}

impl LookupOutcome {
    /// True when the variant is `Created` (regardless of
    /// eviction count). Mirrors the previous bare-variant
    /// matcher so callers don't need to re-pattern.
    #[must_use]
    pub const fn is_created(&self) -> bool {
        matches!(self, Self::Created { .. })
    }
}

impl ConnTable {
    /// Construct an empty conntrack table.
    #[must_use]
    pub fn new(config: ConnTableConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner {
                forward: HashMap::new(),
                reverse: HashMap::new(),
            }),
        }
    }

    /// Convenience constructor with default config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ConnTableConfig::default())
    }

    /// Look up a flow by `key`. If the table holds a forward
    /// entry, returns `ExistingForward` and copies the entry
    /// to `out`. If the table holds a reverse entry
    /// (`key.reverse()` is the originator), returns
    /// `ExistingReverse` and copies the originator entry to
    /// `out`. Otherwise mints a new entry, inserts it into
    /// both maps, and returns `Created`.
    ///
    /// `direction` is the direction the caller observed the
    /// packet on; it's stored in [`FlowState::direction`] on
    /// first creation. On subsequent calls the stored
    /// direction is left alone (the very first observation
    /// wins).
    ///
    /// # Errors
    ///
    /// [`FwError::ConntrackFull`] if the table is at
    /// capacity and the eviction policy could not free a
    /// slot. The caller should fail the flow closed (or
    /// open, depending on its posture) and surface the
    /// pressure on a metric.
    pub fn lookup_or_create(
        &self,
        key: FlowKey,
        direction: FlowDirection,
        now_ms: u64,
    ) -> Result<(LookupOutcome, ConnTrackEntry), FwError> {
        let mut g = self.inner.lock();
        if let Some(entry) = g.forward.get(&key) {
            return Ok((LookupOutcome::ExistingForward, entry.clone()));
        }
        if let Some(forward_key) = g.reverse.get(&key).copied() {
            if let Some(entry) = g.forward.get(&forward_key) {
                return Ok((LookupOutcome::ExistingReverse, entry.clone()));
            }
        }
        // New flow.
        let mut evicted_for_capacity: u32 = 0;
        if g.forward.len() >= self.config.max_entries {
            // Evict the entry with the smallest
            // `last_seen_ms`.
            let victim = g
                .forward
                .iter()
                .min_by_key(|(_, e)| e.state.last_seen_ms)
                .map(|(k, _)| *k);
            if let Some(v) = victim {
                Self::remove_locked(&mut g, &v);
                evicted_for_capacity = evicted_for_capacity.saturating_add(1);
            } else {
                let pressure_pct = 100u8;
                return Err(FwError::ConntrackFull { pressure_pct });
            }
            if g.forward.len() >= self.config.max_entries {
                // Eviction didn't help — table is genuinely
                // full and all entries are the same age.
                let pressure_pct = 100u8;
                return Err(FwError::ConntrackFull { pressure_pct });
            }
        }
        let state = FlowState::new(key.protocol, direction, now_ms);
        let entry = ConnTrackEntry {
            flow_key: key,
            state,
        };
        g.forward.insert(key, entry.clone());
        g.reverse.insert(key.reverse(), key);
        Ok((
            LookupOutcome::Created {
                evicted_for_capacity,
            },
            entry,
        ))
    }

    /// Apply a mutation closure to the entry for `key`. The
    /// closure receives an `&mut FlowState` and may freely
    /// update counters, conn state, app id. Returns whether
    /// the entry existed (and the closure ran).
    #[must_use]
    pub fn with_entry<F>(&self, key: &FlowKey, f: F) -> bool
    where
        F: FnOnce(&mut FlowState),
    {
        let mut g = self.inner.lock();
        if let Some(entry) = g.forward.get_mut(key) {
            f(&mut entry.state);
            true
        } else {
            false
        }
    }

    /// Remove a single entry. Used by the service when a
    /// flow's conn state has reached `Closed` and the
    /// telemetry envelope has been emitted.
    pub fn remove(&self, key: &FlowKey) -> Option<ConnTrackEntry> {
        let mut g = self.inner.lock();
        Self::remove_locked(&mut g, key)
    }

    fn remove_locked(inner: &mut Inner, key: &FlowKey) -> Option<ConnTrackEntry> {
        let entry = inner.forward.remove(key)?;
        inner.reverse.remove(&key.reverse());
        Some(entry)
    }

    /// Drop entries whose idle timeout has elapsed. Returns
    /// the entries that were dropped so the caller can emit
    /// final `FlowEvent`s for them.
    pub fn sweep_idle(&self, now_ms: u64) -> Vec<ConnTrackEntry> {
        let mut g = self.inner.lock();
        let mut dropped = Vec::new();
        // We can't mutate the map while iterating it, so
        // collect victims first, then remove.
        let victims: Vec<FlowKey> = g
            .forward
            .iter()
            .filter_map(|(k, e)| {
                let idle_ms = self
                    .config
                    .idle_for(k.protocol, e.state.conn_state)
                    .as_millis();
                // Clamp via try_from: `as u64` would silently
                // wrap a `Duration::MAX` configuration into a
                // shorter timeout. The conntrack window is
                // measured in seconds-to-minutes; anything that
                // overflows u64 nanos has already been clipped
                // by [`ConnTableConfig`] validation.
                let idle = u64::try_from(idle_ms).unwrap_or(u64::MAX);
                let elapsed = now_ms.saturating_sub(e.state.last_seen_ms);
                if e.state.conn_state == ConnState::Closed || elapsed >= idle {
                    Some(*k)
                } else {
                    None
                }
            })
            .collect();
        for k in victims {
            if let Some(e) = Self::remove_locked(&mut g, &k) {
                dropped.push(e);
            }
        }
        dropped
    }

    /// Current number of forward entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().forward.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().forward.is_empty()
    }

    /// Snapshot a single entry by key, for read-only paths
    /// (telemetry emission, ops dashboards) that should not
    /// mutate state.
    #[must_use]
    pub fn snapshot(&self, key: &FlowKey) -> Option<ConnTrackEntry> {
        self.inner.lock().forward.get(key).cloned()
    }

    /// Current capacity utilisation as a percentage 0..=100.
    /// Used by the service to populate the
    /// `ConntrackFull::pressure_pct` field when the table
    /// genuinely fills up.
    #[must_use]
    pub fn utilisation_pct(&self) -> u8 {
        let g = self.inner.lock();
        let cap = self.config.max_entries.max(1);
        let used = g.forward.len();
        let pct = used.saturating_mul(100) / cap;
        u8::try_from(pct.min(100)).unwrap_or(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn k(port: u16, proto: IpProtocol) -> FlowKey {
        FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            54_321,
            port,
            proto,
        )
        .unwrap()
    }

    #[test]
    fn lookup_creates_when_absent() {
        let t = ConnTable::with_defaults();
        let (outcome, entry) = t
            .lookup_or_create(k(443, IpProtocol::Tcp), FlowDirection::Egress, 1_000)
            .unwrap();
        assert_eq!(
            outcome,
            LookupOutcome::Created {
                evicted_for_capacity: 0
            }
        );
        assert_eq!(entry.flow_key, k(443, IpProtocol::Tcp));
        assert_eq!(entry.state.conn_state, ConnState::SynSent);
        assert_eq!(entry.state.start_ms, 1_000);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn lookup_hits_forward_on_second_packet() {
        let t = ConnTable::with_defaults();
        t.lookup_or_create(k(443, IpProtocol::Tcp), FlowDirection::Egress, 1_000)
            .unwrap();
        let (outcome, _) = t
            .lookup_or_create(k(443, IpProtocol::Tcp), FlowDirection::Egress, 1_100)
            .unwrap();
        assert_eq!(outcome, LookupOutcome::ExistingForward);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn lookup_hits_reverse_for_reply_packet() {
        let t = ConnTable::with_defaults();
        let fwd = k(443, IpProtocol::Tcp);
        t.lookup_or_create(fwd, FlowDirection::Egress, 1_000)
            .unwrap();
        // Server replies — the packet's 5-tuple is the reverse.
        let (outcome, entry) = t
            .lookup_or_create(fwd.reverse(), FlowDirection::Ingress, 1_100)
            .unwrap();
        assert_eq!(outcome, LookupOutcome::ExistingReverse);
        // The returned entry must be the originator's, not
        // a new one keyed on the reverse tuple.
        assert_eq!(entry.flow_key, fwd);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn with_entry_mutates_state_when_present() {
        let t = ConnTable::with_defaults();
        let key = k(443, IpProtocol::Tcp);
        t.lookup_or_create(key, FlowDirection::Egress, 1_000)
            .unwrap();
        let ran = t.with_entry(&key, |state| {
            state.observe_originator(1500, 1_500);
            state.advance_tcp(0x12);
        });
        assert!(ran);
        let snap = t.snapshot(&key).unwrap();
        assert_eq!(snap.state.bytes_originator, 1500);
        assert_eq!(snap.state.last_seen_ms, 1_500);
        assert_eq!(snap.state.conn_state, ConnState::SynReceived);
    }

    #[test]
    fn with_entry_returns_false_when_absent() {
        let t = ConnTable::with_defaults();
        let ran = t.with_entry(&k(443, IpProtocol::Tcp), |_| {});
        assert!(!ran);
    }

    #[test]
    fn remove_drops_both_indices() {
        let t = ConnTable::with_defaults();
        let key = k(443, IpProtocol::Tcp);
        t.lookup_or_create(key, FlowDirection::Egress, 1_000)
            .unwrap();
        let removed = t.remove(&key).expect("entry was present");
        assert_eq!(removed.flow_key, key);
        assert_eq!(t.len(), 0);
        // Reverse-direction lookup must NOT find the
        // removed entry.
        let (outcome, _) = t
            .lookup_or_create(key.reverse(), FlowDirection::Ingress, 1_100)
            .unwrap();
        assert!(outcome.is_created());
    }

    #[test]
    fn sweep_idle_drops_stateless_after_timeout() {
        let cfg = ConnTableConfig {
            max_entries: 8,
            tcp_established_idle: Duration::from_secs(600),
            tcp_closing_idle: Duration::from_secs(5),
            stateless_idle: Duration::from_secs(10),
        };
        let t = ConnTable::new(cfg);
        let key = k(53, IpProtocol::Udp);
        t.lookup_or_create(key, FlowDirection::Egress, 0).unwrap();
        // Just under the idle threshold.
        assert!(t.sweep_idle(9_999).is_empty());
        assert_eq!(t.len(), 1);
        // At the threshold.
        let dropped = t.sweep_idle(10_000);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].flow_key, key);
        assert!(t.is_empty());
    }

    #[test]
    fn sweep_idle_drops_closed_immediately() {
        let t = ConnTable::with_defaults();
        let key = k(443, IpProtocol::Tcp);
        t.lookup_or_create(key, FlowDirection::Egress, 1_000)
            .unwrap();
        // Walk the state machine into Closed.
        let ran = t.with_entry(&key, |state| {
            state.advance_tcp(0x12); // SYN+ACK
            state.advance_tcp(0x10); // ACK
            state.advance_tcp(0x04); // RST
            assert_eq!(state.conn_state, ConnState::Closed);
        });
        assert!(ran);
        // Even at the same instant, Closed entries get
        // dropped.
        let dropped = t.sweep_idle(1_000);
        assert_eq!(dropped.len(), 1);
    }

    #[test]
    fn sweep_idle_keeps_established_tcp_under_idle() {
        let t = ConnTable::with_defaults();
        let key = k(443, IpProtocol::Tcp);
        t.lookup_or_create(key, FlowDirection::Egress, 0).unwrap();
        let ran = t.with_entry(&key, |state| {
            state.advance_tcp(0x12);
            state.advance_tcp(0x10);
            assert_eq!(state.conn_state, ConnState::Established);
        });
        assert!(ran);
        // 9 minutes into the flow — well under the 10-min default.
        assert!(t.sweep_idle(540_000).is_empty());
    }

    #[test]
    fn capacity_evicts_oldest_on_insert() {
        let cfg = ConnTableConfig {
            max_entries: 2,
            ..ConnTableConfig::default()
        };
        let t = ConnTable::new(cfg);
        t.lookup_or_create(k(80, IpProtocol::Tcp), FlowDirection::Egress, 0)
            .unwrap();
        t.lookup_or_create(k(443, IpProtocol::Tcp), FlowDirection::Egress, 100)
            .unwrap();
        // Touch the 443 flow so 80 is genuinely the oldest.
        let ran = t.with_entry(&k(443, IpProtocol::Tcp), |s| {
            s.observe_originator(1, 200);
        });
        assert!(ran);
        let (outcome, _) = t
            .lookup_or_create(k(22, IpProtocol::Tcp), FlowDirection::Egress, 300)
            .unwrap();
        assert_eq!(t.len(), 2);
        // 80 should have been evicted.
        assert!(t.snapshot(&k(80, IpProtocol::Tcp)).is_none());
        assert!(t.snapshot(&k(443, IpProtocol::Tcp)).is_some());
        assert!(t.snapshot(&k(22, IpProtocol::Tcp)).is_some());
        // The outcome must report the capacity-eviction so
        // FwService can fold it into `flows_evicted_capacity`.
        assert_eq!(
            outcome,
            LookupOutcome::Created {
                evicted_for_capacity: 1
            }
        );
    }

    #[test]
    fn utilisation_pct_reports_fill_level() {
        let cfg = ConnTableConfig {
            max_entries: 4,
            ..ConnTableConfig::default()
        };
        let t = ConnTable::new(cfg);
        assert_eq!(t.utilisation_pct(), 0);
        t.lookup_or_create(k(80, IpProtocol::Tcp), FlowDirection::Egress, 0)
            .unwrap();
        assert_eq!(t.utilisation_pct(), 25);
        t.lookup_or_create(k(443, IpProtocol::Tcp), FlowDirection::Egress, 100)
            .unwrap();
        t.lookup_or_create(k(22, IpProtocol::Tcp), FlowDirection::Egress, 200)
            .unwrap();
        t.lookup_or_create(k(53, IpProtocol::Udp), FlowDirection::Egress, 300)
            .unwrap();
        assert_eq!(t.utilisation_pct(), 100);
    }

    #[test]
    fn idle_for_returns_protocol_specific_timeouts() {
        let cfg = ConnTableConfig::default();
        assert_eq!(
            cfg.idle_for(IpProtocol::Tcp, ConnState::Established),
            cfg.tcp_established_idle
        );
        assert_eq!(
            cfg.idle_for(IpProtocol::Tcp, ConnState::Closing),
            cfg.tcp_closing_idle
        );
        assert_eq!(
            cfg.idle_for(IpProtocol::Tcp, ConnState::SynSent),
            cfg.tcp_closing_idle
        );
        assert_eq!(
            cfg.idle_for(IpProtocol::Udp, ConnState::Established),
            cfg.stateless_idle
        );
        assert_eq!(
            cfg.idle_for(IpProtocol::Icmp, ConnState::Established),
            cfg.stateless_idle
        );
    }
}
