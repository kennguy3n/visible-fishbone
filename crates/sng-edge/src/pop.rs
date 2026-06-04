// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Multi-tenant cloud Point-of-Presence (PoP) routing.
//!
//! In [`EdgeMode::Pop`](crate::config::EdgeMode::Pop) the same
//! `sng-edge` binary runs as a *shared* inspection point for many
//! tenants instead of a single-tenant branch appliance. Where a
//! site-mode edge owns exactly one [`PolicyEngine`] bound to the
//! tenant in `[identity]`, a PoP holds one engine **per assigned
//! tenant** and demultiplexes each incoming connection to the
//! owning tenant's engine.
//!
//! # Tenant isolation
//!
//! Isolation is the load-bearing security property of a PoP: one
//! tenant's traffic must never be evaluated against — or even be
//! visible to — another tenant's policy. [`PoPRouter`] enforces
//! this structurally. Every connection is resolved to exactly one
//! [`TenantId`] via [`PoPRouter::route`], and evaluation only ever
//! touches that tenant's engine ([`PoPRouter::evaluate`]). There is
//! no API that evaluates a flow against more than one tenant's
//! bundle, and a connection whose tenant is not assigned to this
//! PoP is *denied by construction* (it resolves to a
//! [`RouteError`], never to a fallback engine). A missing tenant
//! therefore fails closed rather than leaking onto a neighbour.
//!
//! # Concurrency
//!
//! The per-tenant engine map is published through an
//! [`ArcSwap`] so the data-plane hot path ([`route`]/[`evaluate`])
//! reads it wait-free, while the control path (bundle pulls adding
//! or dropping tenants) installs a new immutable snapshot via a
//! copy-on-write [`ArcSwap::rcu`]. The connection counter is a
//! single relaxed [`AtomicU64`]. No locks sit on the connection
//! path.
//!
//! [`route`]: PoPRouter::route
//! [`PolicyEngine`]: sng_policy_eval::PolicyEngine

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use sng_core::ids::TenantId;
use sng_policy_eval::{Flow, PolicyEngine, Verdict};
use thiserror::Error;

/// How an incoming connection names the tenant it belongs to.
///
/// `CertClaim` is authoritative: it is the tenant id carried by a
/// verified client certificate, so it is trusted directly.
/// `Sni` is the TLS ServerName from the ClientHello, which the PoP
/// must map to a tenant through its configured SNI table before it
/// can be trusted — an unknown ServerName resolves to
/// [`RouteError::UnknownSni`] rather than to any tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSelector<'a> {
    /// Tenant id asserted by a verified client certificate.
    CertClaim(TenantId),
    /// TLS SNI ServerName, looked up in the PoP's SNI table.
    Sni(&'a str),
}

/// Why a connection could not be bound to a tenant's engine.
///
/// Both variants fail closed — the caller must drop / reject the
/// connection. Neither ever silently falls back to another
/// tenant's policy.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteError {
    /// The SNI ServerName is not mapped to any tenant on this PoP.
    #[error("no tenant mapped for SNI host {sni:?}")]
    UnknownSni {
        /// The unmapped ServerName, echoed back for logging.
        sni: String,
    },
    /// The tenant was named (by cert claim, or via a stale SNI
    /// mapping) but no policy bundle for it is loaded on this PoP —
    /// it is not currently assigned here.
    #[error("tenant {tenant} is not assigned to this PoP")]
    TenantNotAssigned {
        /// The tenant that resolved but has no loaded engine.
        tenant: TenantId,
    },
}

/// Connection refused because the PoP is at its hard admission
/// ceiling. The control plane should have steered this tenant
/// elsewhere; shedding here is the last-resort backstop that keeps
/// one PoP from being driven past its sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("PoP at capacity: {active}/{max} connections")]
pub struct AtCapacity {
    /// Connections in flight when admission was refused.
    pub active: u64,
    /// The configured hard ceiling.
    pub max: u64,
}

/// Immutable snapshot of the tenants a PoP currently serves.
///
/// Published as a unit through [`ArcSwap`]: readers clone the
/// `Arc<PolicyEngine>` they need and the snapshot itself is never
/// mutated in place. `sni` maps a TLS ServerName to the tenant
/// that owns it; `engines` maps a tenant to its compiled bundle.
#[derive(Debug, Default)]
struct TenantTable {
    engines: HashMap<TenantId, Arc<PolicyEngine>>,
    sni: HashMap<String, TenantId>,
}

impl TenantTable {
    /// Clone-with-edit: returns a new table with `tenant` installed
    /// (replacing any existing engine + SNI rows for it). Used by
    /// the copy-on-write [`ArcSwap::rcu`] path.
    fn with_tenant(
        &self,
        tenant: TenantId,
        engine: Arc<PolicyEngine>,
        sni_hosts: &[String],
    ) -> Self {
        let mut engines = self.engines.clone();
        engines.insert(tenant, engine);

        // Drop any SNI rows that previously pointed at this tenant
        // before re-adding the fresh set, so a tenant whose host
        // list shrank does not keep stale aliases.
        let mut sni: HashMap<String, TenantId> = self
            .sni
            .iter()
            .filter(|(_, t)| **t != tenant)
            .map(|(h, t)| (h.clone(), *t))
            .collect();
        for host in sni_hosts {
            sni.insert(host.clone(), tenant);
        }
        Self { engines, sni }
    }

    /// Clone-with-edit: returns a new table with `tenant` and all
    /// of its SNI rows removed.
    fn without_tenant(&self, tenant: TenantId) -> Self {
        let engines = self
            .engines
            .iter()
            .filter(|(t, _)| **t != tenant)
            .map(|(t, e)| (*t, Arc::clone(e)))
            .collect();
        let sni = self
            .sni
            .iter()
            .filter(|(_, t)| **t != tenant)
            .map(|(h, t)| (h.clone(), *t))
            .collect();
        Self { engines, sni }
    }
}

/// A point-in-time view of a PoP's load, sent to the control plane
/// so it can decide whether to rebalance tenants away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityReport {
    /// Connections currently in flight.
    pub active: u64,
    /// Hard admission ceiling (`pop.max_connections`).
    pub max: u64,
    /// Soft high-water mark; at or above this the PoP asks to be
    /// drained.
    pub high_water: u64,
    /// Number of tenants whose bundles are loaded.
    pub tenants: usize,
    /// True iff `active >= high_water` — the rebalance trigger.
    pub overloaded: bool,
}

/// Routes connections on a multi-tenant cloud PoP to the owning
/// tenant's policy engine, and tracks load for capacity
/// management.
///
/// Construct one per PoP process. Clone the `Arc<PoPRouter>` into
/// each connection-accept task; all share the same lock-free
/// tenant table and connection counter.
#[derive(Debug)]
pub struct PoPRouter {
    tenants: ArcSwap<TenantTable>,
    active: AtomicU64,
    max_connections: u64,
    high_water: u64,
}

impl PoPRouter {
    /// Create an empty router sized by `max_connections` (the hard
    /// admission ceiling) and `high_water_fraction` (the fraction
    /// of that ceiling at which the PoP reports itself overloaded).
    ///
    /// `max_connections` is clamped to a floor of 1, and
    /// `high_water_fraction` to `(0, 1]`, so the constructor cannot
    /// produce a degenerate threshold even if handed unvalidated
    /// input; the config layer ([`crate::config`]) rejects bad
    /// values earlier with a friendlier error.
    #[must_use]
    pub fn new(max_connections: u64, high_water_fraction: f64) -> Self {
        let max = max_connections.max(1);
        let frac = if high_water_fraction.is_finite() {
            high_water_fraction.clamp(f64::MIN_POSITIVE, 1.0)
        } else {
            1.0
        };
        Self {
            tenants: ArcSwap::from_pointee(TenantTable::default()),
            active: AtomicU64::new(0),
            max_connections: max,
            high_water: high_water_mark(max, frac),
        }
    }

    /// Install (or replace) a tenant's compiled policy engine and
    /// its SNI aliases. Atomic against concurrent readers: a
    /// connection in flight sees either the old or the new table,
    /// never a torn one.
    pub fn install_tenant(
        &self,
        tenant: TenantId,
        engine: &Arc<PolicyEngine>,
        sni_hosts: &[String],
    ) {
        self.tenants
            .rcu(|cur| Arc::new(cur.with_tenant(tenant, Arc::clone(engine), sni_hosts)));
    }

    /// Drop a tenant (e.g. the control plane rebalanced it away).
    /// Connections already routed keep their cloned engine `Arc`
    /// alive until they close; new lookups for the tenant fail
    /// with [`RouteError::TenantNotAssigned`].
    pub fn remove_tenant(&self, tenant: TenantId) {
        self.tenants.rcu(|cur| Arc::new(cur.without_tenant(tenant)));
    }

    /// Number of tenants whose bundles are currently loaded.
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.tenants.load().engines.len()
    }

    /// True iff `tenant` has a loaded engine on this PoP.
    #[must_use]
    pub fn serves(&self, tenant: TenantId) -> bool {
        self.tenants.load().engines.contains_key(&tenant)
    }

    /// Resolve a connection's [`TenantSelector`] to the tenant that
    /// owns it, *without* loading the engine. A `CertClaim` is
    /// honoured only if that tenant is assigned here; an `Sni` is
    /// resolved through the SNI table, which `with_tenant` /
    /// `without_tenant` keep in lockstep with `engines` within each
    /// snapshot — so an SNI hit always names an assigned tenant.
    ///
    /// # Errors
    ///
    /// [`RouteError::UnknownSni`] if the ServerName maps to no tenant.
    /// [`RouteError::TenantNotAssigned`] only on the `CertClaim` path,
    /// when the asserted tenant has no loaded engine — a cert may
    /// claim any tenant id, so this is the isolation check. The `Sni`
    /// path never returns it, because SNI rows exist only for tenants
    /// that are assigned (and therefore have an engine) in the same
    /// snapshot.
    pub fn resolve(&self, selector: TenantSelector<'_>) -> Result<TenantId, RouteError> {
        let table = self.tenants.load();
        match selector {
            TenantSelector::CertClaim(tenant) => {
                if table.engines.contains_key(&tenant) {
                    Ok(tenant)
                } else {
                    Err(RouteError::TenantNotAssigned { tenant })
                }
            }
            TenantSelector::Sni(host) => match table.sni.get(host) {
                Some(&tenant) => Ok(tenant),
                None => Err(RouteError::UnknownSni {
                    sni: host.to_owned(),
                }),
            },
        }
    }

    /// Resolve a connection to the owning tenant's policy engine.
    /// The returned `Arc` is the *only* engine this connection will
    /// ever touch — the tenant-isolation guarantee.
    ///
    /// # Errors
    ///
    /// See [`resolve`](Self::resolve). A SNI row pointing at a
    /// tenant whose engine was concurrently removed also surfaces
    /// as [`RouteError::TenantNotAssigned`].
    pub fn route(&self, selector: TenantSelector<'_>) -> Result<Arc<PolicyEngine>, RouteError> {
        let table = self.tenants.load();
        let tenant = match selector {
            TenantSelector::CertClaim(tenant) => tenant,
            TenantSelector::Sni(host) => {
                *table.sni.get(host).ok_or_else(|| RouteError::UnknownSni {
                    sni: host.to_owned(),
                })?
            }
        };
        table
            .engines
            .get(&tenant)
            .map(Arc::clone)
            .ok_or(RouteError::TenantNotAssigned { tenant })
    }

    /// Resolve `selector` to its tenant and evaluate `flow` against
    /// that tenant's engine *alone*. This is the isolation
    /// boundary in one call: there is no path by which `flow` is
    /// scored against any other tenant's bundle.
    ///
    /// # Errors
    ///
    /// Propagates [`RouteError`] when the connection cannot be
    /// bound to a loaded tenant.
    pub fn evaluate(
        &self,
        selector: TenantSelector<'_>,
        flow: &Flow<'_>,
    ) -> Result<Verdict, RouteError> {
        Ok(self.route(selector)?.evaluate(flow))
    }

    /// Try to admit a new connection. On success returns an RAII
    /// [`ConnGuard`] that decrements the live-connection counter
    /// when dropped; on refusal returns [`AtCapacity`].
    ///
    /// The increment-then-check uses a compare-and-swap loop so the
    /// counter never transiently exceeds `max_connections` (a naive
    /// `fetch_add` then roll-back would briefly publish an
    /// over-ceiling count to a concurrent [`capacity_report`]).
    ///
    /// [`capacity_report`]: Self::capacity_report
    ///
    /// # Errors
    ///
    /// [`AtCapacity`] when the hard ceiling is already reached.
    pub fn admit(&self) -> Result<ConnGuard<'_>, AtCapacity> {
        let mut cur = self.active.load(Ordering::Relaxed);
        loop {
            if cur >= self.max_connections {
                return Err(AtCapacity {
                    active: cur,
                    max: self.max_connections,
                });
            }
            match self.active.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(ConnGuard {
                        counter: &self.active,
                    });
                }
                Err(observed) => cur = observed,
            }
        }
    }

    /// Connections currently in flight.
    #[must_use]
    pub fn active_connections(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// True iff load has reached the high-water mark — the signal
    /// the control plane uses to rebalance tenants off this PoP.
    #[must_use]
    pub fn is_overloaded(&self) -> bool {
        self.active_connections() >= self.high_water
    }

    /// Snapshot the PoP's load for the control plane.
    #[must_use]
    pub fn capacity_report(&self) -> CapacityReport {
        let active = self.active_connections();
        CapacityReport {
            active,
            max: self.max_connections,
            high_water: self.high_water,
            tenants: self.tenant_count(),
            overloaded: active >= self.high_water,
        }
    }

    /// A [`CapacityReport`] iff the PoP is overloaded, else `None`.
    /// Lets a beacon loop cheaply gate "do I need to ask for a
    /// rebalance?" without branching on a bare bool.
    #[must_use]
    pub fn rebalance_signal(&self) -> Option<CapacityReport> {
        let report = self.capacity_report();
        report.overloaded.then_some(report)
    }
}

/// Compute the high-water connection count from the ceiling and a
/// validated fraction in `(0, 1]`. Split out so the lossy float
/// arithmetic is isolated behind one documented cast.
fn high_water_mark(max: u64, frac: f64) -> u64 {
    // `max` is a connection count (≤ a few million in practice);
    // `frac` ∈ (0, 1]. The product is therefore in [0, max] and the
    // ceil + clamp keep it there, so the `as u64` is exact and
    // never truncates or wraps. We clamp the *float* to [1, max]
    // before the cast and floor the result at 1 so even `max == 1`
    // yields a usable (reachable) threshold.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let raw = ((max as f64) * frac).ceil().clamp(1.0, max as f64) as u64;
    raw.max(1)
}

/// RAII counter guard returned by [`PoPRouter::admit`]. Holding it
/// represents one live connection; dropping it releases the slot.
/// Connection-handling code keeps the guard alive for the lifetime
/// of the connection (e.g. as a field on the per-connection task
/// state) and lets the `Drop` impl do the accounting.
#[derive(Debug)]
pub struct ConnGuard<'a> {
    counter: &'a AtomicU64,
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::policy::BundleTarget;
    use sng_policy_eval::{EnforcementDomain, FlowBuilder};
    use std::net::{IpAddr, Ipv4Addr};

    // A deny-all engine is enough for routing/isolation tests: we
    // assert *which* engine a connection reaches, and a deny-all
    // bundle gives a deterministic `Verdict::Deny` to compare
    // against.
    fn deny_engine() -> Arc<PolicyEngine> {
        let body = sng_policy_eval::deny_all_skeleton_body(BundleTarget::Edge);
        Arc::new(PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap())
    }

    fn sample_flow<'a>() -> Flow<'a> {
        FlowBuilder::new(EnforcementDomain::Dns)
            .destination_host("example.com")
            .source_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .build()
    }

    #[test]
    fn install_and_route_by_cert_claim() {
        let router = PoPRouter::new(1000, 0.85);
        let tenant = TenantId::new_v4();
        router.install_tenant(tenant, &deny_engine(), &[]);

        assert_eq!(router.tenant_count(), 1);
        assert!(router.serves(tenant));
        let engine = router
            .route(TenantSelector::CertClaim(tenant))
            .expect("assigned tenant routes");
        assert_eq!(engine.target(), BundleTarget::Edge);
    }

    #[test]
    fn route_by_sni_alias() {
        let router = PoPRouter::new(1000, 0.85);
        let tenant = TenantId::new_v4();
        router.install_tenant(
            tenant,
            &deny_engine(),
            &["acme.edge.sng.example.com".to_owned()],
        );

        let tid = router
            .resolve(TenantSelector::Sni("acme.edge.sng.example.com"))
            .expect("known SNI resolves");
        assert_eq!(tid, tenant);
        assert!(
            router
                .route(TenantSelector::Sni("acme.edge.sng.example.com"))
                .is_ok()
        );
    }

    #[test]
    fn unknown_sni_fails_closed() {
        let router = PoPRouter::new(1000, 0.85);
        let err = router
            .route(TenantSelector::Sni("stranger.example.com"))
            .expect_err("unknown SNI must not route");
        assert_eq!(
            err,
            RouteError::UnknownSni {
                sni: "stranger.example.com".to_owned()
            }
        );
    }

    #[test]
    fn unassigned_cert_claim_fails_closed() {
        let router = PoPRouter::new(1000, 0.85);
        let stranger = TenantId::new_v4();
        let err = router
            .route(TenantSelector::CertClaim(stranger))
            .expect_err("unassigned tenant must not route");
        assert_eq!(err, RouteError::TenantNotAssigned { tenant: stranger });
    }

    // The core isolation property: a flow only ever reaches the
    // engine of the tenant it was routed to. We install two tenants
    // and confirm neither selector can reach the other's engine.
    #[test]
    fn tenants_are_isolated() {
        let router = PoPRouter::new(1000, 0.85);
        let alpha = TenantId::new_v4();
        let bravo = TenantId::new_v4();
        let alpha_engine = deny_engine();
        let bravo_engine = deny_engine();
        router.install_tenant(alpha, &alpha_engine, &["a.example.com".to_owned()]);
        router.install_tenant(bravo, &bravo_engine, &["b.example.com".to_owned()]);

        let routed_a = router.route(TenantSelector::Sni("a.example.com")).unwrap();
        let routed_b = router.route(TenantSelector::Sni("b.example.com")).unwrap();
        // Each SNI reaches its OWN tenant's engine instance and not
        // the neighbour's.
        assert!(Arc::ptr_eq(&routed_a, &alpha_engine));
        assert!(Arc::ptr_eq(&routed_b, &bravo_engine));
        assert!(!Arc::ptr_eq(&routed_a, &bravo_engine));

        // Evaluation goes through the routed engine alone.
        let flow = sample_flow();
        assert_eq!(
            router
                .evaluate(TenantSelector::CertClaim(alpha), &flow)
                .unwrap(),
            Verdict::Deny
        );
    }

    #[test]
    fn remove_tenant_drops_routes_but_keeps_inflight_engine() {
        let router = PoPRouter::new(1000, 0.85);
        let tenant = TenantId::new_v4();
        router.install_tenant(tenant, &deny_engine(), &["gone.example.com".to_owned()]);

        // A connection routed BEFORE removal keeps a live handle.
        let inflight = router.route(TenantSelector::CertClaim(tenant)).unwrap();

        router.remove_tenant(tenant);
        assert!(!router.serves(tenant));
        assert_eq!(router.tenant_count(), 0);
        // New lookups by either selector now fail closed.
        assert_eq!(
            router
                .route(TenantSelector::CertClaim(tenant))
                .expect_err("removed tenant must not route"),
            RouteError::TenantNotAssigned { tenant }
        );
        assert!(
            router
                .route(TenantSelector::Sni("gone.example.com"))
                .is_err()
        );
        // The in-flight engine is still usable for its connection.
        assert_eq!(inflight.evaluate(&sample_flow()), Verdict::Deny);
    }

    #[test]
    fn reinstall_replaces_stale_sni_aliases() {
        let router = PoPRouter::new(1000, 0.85);
        let tenant = TenantId::new_v4();
        router.install_tenant(tenant, &deny_engine(), &["old.example.com".to_owned()]);
        // Re-publish the tenant with a different host set; the old
        // alias must not linger.
        router.install_tenant(tenant, &deny_engine(), &["new.example.com".to_owned()]);

        assert!(router.route(TenantSelector::Sni("new.example.com")).is_ok());
        assert_eq!(
            router
                .route(TenantSelector::Sni("old.example.com"))
                .expect_err("stale SNI alias must not route"),
            RouteError::UnknownSni {
                sni: "old.example.com".to_owned()
            }
        );
        // Still exactly one tenant — reinstall replaced, not added.
        assert_eq!(router.tenant_count(), 1);
    }

    #[test]
    fn admit_sheds_at_hard_ceiling() {
        let router = PoPRouter::new(2, 1.0);
        let g1 = router.admit().expect("1st admit");
        let _g2 = router.admit().expect("2nd admit");
        assert_eq!(router.active_connections(), 2);

        // Third connection is shed at the ceiling.
        let err = router.admit().expect_err("at capacity");
        assert_eq!(err, AtCapacity { active: 2, max: 2 });

        // Dropping a guard frees a slot for a retry.
        drop(g1);
        assert_eq!(router.active_connections(), 1);
        assert!(router.admit().is_ok());
    }

    #[test]
    fn overload_trips_at_high_water() {
        // max 10, high-water fraction 0.8 -> threshold 8.
        let router = PoPRouter::new(10, 0.8);
        assert_eq!(router.capacity_report().high_water, 8);

        let mut guards = Vec::new();
        for _ in 0..7 {
            guards.push(router.admit().unwrap());
        }
        assert!(!router.is_overloaded());
        assert!(router.rebalance_signal().is_none());

        guards.push(router.admit().unwrap()); // 8th -> at high-water
        assert!(router.is_overloaded());
        let signal = router.rebalance_signal().expect("overloaded -> signal");
        assert_eq!(signal.active, 8);
        assert_eq!(signal.high_water, 8);
        assert_eq!(signal.max, 10);
        assert!(signal.overloaded);
    }

    #[test]
    fn high_water_mark_is_bounded() {
        // Degenerate inputs must still yield a reachable threshold
        // in [1, max].
        assert_eq!(high_water_mark(1, 1.0), 1);
        assert_eq!(high_water_mark(100, 0.85), 85);
        // ceil rounds up so a fractional product never floors to 0.
        assert_eq!(high_water_mark(10, 0.01), 1);
        // new() clamps a non-finite fraction to 1.0 (== max).
        let router = PoPRouter::new(50, f64::NAN);
        assert_eq!(router.capacity_report().high_water, 50);
    }
}
