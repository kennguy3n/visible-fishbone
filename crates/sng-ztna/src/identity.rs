//! Identity provider.
//!
//! Given a user id verified by the upstream IdP (the
//! `sub` claim from an OIDC token, or a SPIFFE ID from
//! mTLS), the identity provider returns the user's
//! groups + MFA freshness. The ZTNA service uses these
//! to evaluate the app's `required_groups` set and the
//! policy's MFA-freshness threshold.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// One user's identity record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentity {
    /// Stable user id (`sub` claim from OIDC, or SPIFFE
    /// ID). Used by the data path to attribute a
    /// request to a user.
    pub user_id: String,
    /// Tenant the user belongs to.
    pub tenant_id: String,
    /// Identity groups (RBAC roles). The app's
    /// `required_groups` must intersect this set for
    /// access to be granted.
    pub groups: HashSet<String>,
    /// When the user last completed MFA (millisecond
    /// epoch, monotonic on the IdP).
    pub mfa_at_ms: u64,
    /// Free-form user tags from the control-plane bundle
    /// (e.g. `risk_tier=elevated`, `department=finance`).
    /// Evaluated against
    /// [`crate::policy::AccessConditions::user_tag_conditions`].
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

impl UserIdentity {
    /// True iff the user's MFA is no older than
    /// `max_age_ms` relative to `now_ms`. Same
    /// forward-skew tolerance as
    /// [`crate::device::DeviceTrust::posture_fresh`].
    #[must_use]
    pub fn mfa_fresh(&self, now_ms: u64, max_age_ms: u64) -> bool {
        now_ms.saturating_sub(self.mfa_at_ms).le(&max_age_ms)
    }
}

/// Identity provider. Production swaps a tenant-aware
/// implementation (e.g. IdP-backed cache) behind this
/// trait.
pub trait IdentityProvider: Send + Sync + 'static {
    /// Look up `user_id`.
    ///
    /// Returns `None` when the user is not registered.
    /// The orchestrator translates this into a deny with
    /// reason `identity_not_found`.
    fn get(&self, user_id: &str) -> Option<UserIdentity>;
}

/// In-memory provider with `ArcSwap` semantics — the
/// IdP-sync task refreshes whole snapshots (users x
/// tenants) every minute or so, and the data path reads
/// without taking a lock.
#[derive(Debug, Default)]
pub struct StaticIdentityProvider {
    by_user: ArcSwap<HashMap<String, UserIdentity>>,
}

impl StaticIdentityProvider {
    /// Construct from a list of identities.
    #[must_use]
    pub fn new(users: Vec<UserIdentity>) -> Self {
        let table = users
            .into_iter()
            .map(|u| (u.user_id.clone(), u))
            .collect::<HashMap<_, _>>();
        Self {
            by_user: ArcSwap::new(Arc::new(table)),
        }
    }

    /// Replace the entire table atomically.
    pub fn replace(&self, users: Vec<UserIdentity>) {
        let table = users
            .into_iter()
            .map(|u| (u.user_id.clone(), u))
            .collect::<HashMap<_, _>>();
        self.by_user.store(Arc::new(table));
    }

    /// Insert or update a single user subject, keyed by its
    /// [`UserIdentity::user_id`].
    ///
    /// This is the per-subject feed the enforcement-plane
    /// producer (`sng-edge`) uses to thread a *verified user
    /// subject* — resolved from the IdP / mTLS chain, e.g.
    /// via [`crate::oidc_identity::identity_from_claims`] —
    /// into the table the access path and the continuous
    /// re-evaluation loop both read. Where [`Self::replace`]
    /// swaps the whole table for the control-plane IdP-sync
    /// snapshot, `upsert` lets the data path register the
    /// single subject it just authenticated without waiting
    /// for the next bulk sync, so a real user's groups / MFA
    /// freshness drive the verdict immediately rather than
    /// degrading to [`crate::ZtnaDecisionReason::IdentityAbsent`].
    ///
    /// Copy-on-write under a compare-and-swap retry loop
    /// ([`ArcSwap::rcu`]): clones the *currently committed*
    /// table, applies the upsert, and commits only if the
    /// table has not been swapped in the meantime — otherwise
    /// it re-clones from the new snapshot and retries. In-flight
    /// readers keep the snapshot they already loaded, so the
    /// read path stays lock-free.
    ///
    /// The retry is what makes concurrent producers safe: two
    /// simultaneous `upsert`s, or an `upsert` racing the bulk
    /// [`Self::replace`] IdP sync, can never lose each other's
    /// write the way a plain load-modify-store would (the loser
    /// of the CAS re-applies onto the winner's table). A
    /// `replace` that lands *after* a committed `upsert` still
    /// supersedes it — by design, the bulk sync is authoritative
    /// and the single subject re-registers on its next session
    /// event. This is an off-request-path operation (the
    /// producer calls it when a session authenticates, not per
    /// access evaluation), so the clone-and-retry cost is
    /// acceptable for the lock-free read guarantee it preserves.
    /// Takes the subject by reference: the compare-and-swap
    /// retry may run the closure more than once, so the value
    /// is cloned into the snapshot per attempt rather than
    /// consumed.
    pub fn upsert(&self, user: &UserIdentity) {
        self.by_user.rcu(|current| {
            let mut table = HashMap::clone(current);
            table.insert(user.user_id.clone(), user.clone());
            Arc::new(table)
        });
    }

    /// Remove a single user subject by id, returning `true`
    /// if it was present in the committed table. The mirror of
    /// [`Self::upsert`] for the producer to forget a subject
    /// when its session ends (so the re-eval loop stops
    /// resolving a stale subject), using the same
    /// [`ArcSwap::rcu`] compare-and-swap retry so it never races
    /// a concurrent `upsert` / `replace` into a lost update.
    /// `removed` reflects the final committed iteration.
    pub fn remove(&self, user_id: &str) -> bool {
        let mut removed = false;
        self.by_user.rcu(|current| {
            let mut table = HashMap::clone(current);
            removed = table.remove(user_id).is_some();
            Arc::new(table)
        });
        removed
    }

    /// Snapshot the live table.
    #[must_use]
    pub fn snapshot(&self) -> Arc<HashMap<String, UserIdentity>> {
        self.by_user.load_full()
    }

    /// Number of users in the provider.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_user.load().len()
    }

    /// True iff the provider has no users.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_user.load().is_empty()
    }
}

impl IdentityProvider for StaticIdentityProvider {
    fn get(&self, user_id: &str) -> Option<UserIdentity> {
        self.by_user.load().get(user_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn user(id: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
        UserIdentity {
            user_id: id.into(),
            tenant_id: "t1".into(),
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            mfa_at_ms,
            tags: HashMap::new(),
        }
    }

    #[test]
    fn new_indexes_by_user_id() {
        let p = StaticIdentityProvider::new(vec![user("alice", &["eng"], 1_000)]);
        assert_eq!(p.get("alice").unwrap().tenant_id, "t1");
        assert!(p.get("bob").is_none());
    }

    #[test]
    fn replace_swaps_atomically() {
        let p = StaticIdentityProvider::new(vec![user("alice", &[], 0)]);
        p.replace(vec![user("bob", &[], 0)]);
        assert!(p.get("alice").is_none());
        assert!(p.get("bob").is_some());
    }

    #[test]
    fn mfa_fresh_respects_max_age() {
        let u = user("alice", &[], 500);
        assert!(u.mfa_fresh(1_000, 1_000));
        assert!(u.mfa_fresh(1_500, 1_000));
        assert!(!u.mfa_fresh(2_000, 1_000));
    }

    #[test]
    fn mfa_fresh_tolerates_forward_skew() {
        let u = user("alice", &[], 10_000);
        assert!(u.mfa_fresh(1_000, 1_000));
    }

    #[test]
    fn len_and_is_empty_reflect_table_size() {
        let p = StaticIdentityProvider::default();
        assert!(p.is_empty());
        p.replace(vec![user("a", &[], 0), user("b", &[], 0)]);
        assert_eq!(p.len(), 2);
        assert!(!p.is_empty());
    }

    #[test]
    fn upsert_inserts_then_overwrites() {
        let p = StaticIdentityProvider::default();
        p.upsert(&user("alice", &["eng"], 100));
        assert_eq!(p.get("alice").unwrap().mfa_at_ms, 100);
        // Same key overwrites in place.
        p.upsert(&user("alice", &["eng", "admin"], 200));
        let got = p.get("alice").unwrap();
        assert_eq!(got.mfa_at_ms, 200);
        assert!(got.groups.contains("admin"));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn remove_reports_presence() {
        let p = StaticIdentityProvider::new(vec![user("alice", &[], 0)]);
        assert!(p.remove("alice"));
        assert!(p.get("alice").is_none());
        // Removing an absent subject is a no-op reporting false.
        assert!(!p.remove("alice"));
    }

    #[test]
    fn concurrent_upserts_do_not_lose_writes() {
        // Regression: a plain load-clone-store loses updates when
        // producers race (one store clobbers another's insert). The
        // `rcu` CAS-retry must preserve every distinct write.
        use std::thread;
        let p = Arc::new(StaticIdentityProvider::default());
        let n: usize = 128;
        let threads: Vec<_> = (0..n)
            .map(|i| {
                let p = Arc::clone(&p);
                thread::spawn(move || p.upsert(&user(&format!("u{i}"), &[], 0)))
            })
            .collect();
        for t in threads {
            t.join().expect("thread panicked");
        }
        assert_eq!(p.len(), n, "concurrent upserts lost writes");
        for i in 0..n {
            assert!(p.get(&format!("u{i}")).is_some(), "u{i} was lost");
        }
    }

    #[test]
    fn concurrent_upserts_never_clobber_a_bulk_replace() {
        // An `upsert` racing the bulk IdP-sync `replace` must never
        // wipe the synced cohort: the loser of the CAS re-applies onto
        // the winner's table. After the dust settles every replaced
        // user is still resolvable.
        use std::thread;
        let p = Arc::new(StaticIdentityProvider::default());
        let cohort: Vec<UserIdentity> = (0..200usize)
            .map(|i| user(&format!("sync{i}"), &[], 0))
            .collect();
        let writer = {
            let p = Arc::clone(&p);
            let cohort = cohort.clone();
            thread::spawn(move || p.replace(cohort))
        };
        let upserts: Vec<_> = (0..64usize)
            .map(|i| {
                let p = Arc::clone(&p);
                thread::spawn(move || p.upsert(&user(&format!("session{i}"), &[], 0)))
            })
            .collect();
        writer.join().expect("writer panicked");
        for t in upserts {
            t.join().expect("thread panicked");
        }
        for i in 0..200usize {
            assert!(
                p.get(&format!("sync{i}")).is_some(),
                "bulk-synced sync{i} was clobbered by a racing upsert"
            );
        }
    }
}
