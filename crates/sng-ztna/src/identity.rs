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
}
