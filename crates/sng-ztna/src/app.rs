//! App catalog.
//!
//! The catalog is the per-tenant list of applications
//! ZTNA brokers access to. Each [`App`] declares:
//!
//! - `app_id` — opaque stable id, the key the data path
//!   carries on every access request.
//! - `display_name` — human-readable label used by the
//!   ops dashboards.
//! - `host_patterns` — the FQDNs / IPs that, when seen by
//!   the proxy, resolve to this app. (The brain itself
//!   does not match against the network; the catalog
//!   carries the patterns so out-of-band tools — like
//!   the bundle exporter — can keep their indexes
//!   consistent with the runtime catalog.)
//! - `required_groups` — at least one of the user's
//!   identity groups must be in this set. Empty set
//!   means "any authenticated user".
//! - `posture_requirement` — minimum
//!   [`crate::policy::PostureRequirement`] the device
//!   must meet.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::policy::{AccessConditions, PostureRequirement};

/// One application in the per-tenant catalog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    /// Opaque stable id.
    pub app_id: String,
    /// Human-readable label.
    pub display_name: String,
    /// Network locators (FQDN / IP / CIDR) the data
    /// path uses to attribute a request to this app.
    pub host_patterns: Vec<String>,
    /// Identity groups (at least one of which the user
    /// must belong to). Empty = any authenticated user.
    pub required_groups: HashSet<String>,
    /// Minimum device posture required to access.
    pub posture_requirement: PostureRequirement,
    /// Per-app override of the policy-global MFA freshness
    /// budget (`policy.mfa_max_age_ms`). `None` = use the
    /// policy default; `Some(ms)` lets a high-risk app
    /// demand more-frequent MFA (e.g. 30 min) while
    /// low-risk apps keep the 8-hour default.
    #[serde(default)]
    pub mfa_max_age_override_ms: Option<u64>,
    /// Contextual access conditions (geo / network / time
    /// / tags). Defaults to an unconstrained
    /// [`AccessConditions`], so existing catalog entries
    /// admit any request.
    #[serde(default)]
    pub conditions: AccessConditions,
    /// Free-form tags from the control-plane bundle (e.g.
    /// `sensitivity=high`). Foundation for attribute-based
    /// policy; carried for now, not yet gated on directly.
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

impl App {
    /// Convenience constructor for tests. New optional
    /// fields ([`Self::mfa_max_age_override_ms`],
    /// [`Self::conditions`], [`Self::tags`]) default to
    /// "unset" so callers get the pre-existing behaviour.
    #[must_use]
    pub fn new(app_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            display_name: display_name.into(),
            host_patterns: Vec::new(),
            required_groups: HashSet::new(),
            posture_requirement: PostureRequirement::NONE,
            mfa_max_age_override_ms: None,
            conditions: AccessConditions::default(),
            tags: HashMap::new(),
        }
    }
}

/// Catalog provider. Production swaps a tenant-aware
/// implementation (e.g. NATS-backed) behind this trait.
pub trait AppCatalogProvider: Send + Sync + 'static {
    /// Look up an app by id.
    ///
    /// Returns `None` when the app is not in the catalog.
    /// The orchestrator translates this into a deny with
    /// reason `unknown_app`.
    fn get(&self, app_id: &str) -> Option<App>;
}

/// In-memory provider. Tables are stored in
/// [`ArcSwap`] so the data path can read without a lock
/// and the bundle adapter can swap whole catalogs
/// atomically.
#[derive(Debug, Default)]
pub struct StaticAppCatalog {
    by_id: ArcSwap<HashMap<String, App>>,
}

impl StaticAppCatalog {
    /// Construct from a flat list of apps.
    #[must_use]
    pub fn new(apps: Vec<App>) -> Self {
        let table = apps
            .into_iter()
            .map(|a| (a.app_id.clone(), a))
            .collect::<HashMap<_, _>>();
        Self {
            by_id: ArcSwap::new(Arc::new(table)),
        }
    }

    /// Replace the entire catalog atomically. In-flight
    /// evaluations see the old table until they finish.
    pub fn replace(&self, apps: Vec<App>) {
        let table = apps
            .into_iter()
            .map(|a| (a.app_id.clone(), a))
            .collect::<HashMap<_, _>>();
        self.by_id.store(Arc::new(table));
    }

    /// Snapshot the live table (cheap — clones the
    /// `Arc`).
    #[must_use]
    pub fn snapshot(&self) -> Arc<HashMap<String, App>> {
        self.by_id.load_full()
    }

    /// Number of apps currently in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.load().len()
    }

    /// True iff the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.load().is_empty()
    }
}

impl AppCatalogProvider for StaticAppCatalog {
    fn get(&self, app_id: &str) -> Option<App> {
        self.by_id.load().get(app_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn new_indexes_by_app_id() {
        let cat = StaticAppCatalog::new(vec![App::new("wiki", "Wiki")]);
        assert_eq!(cat.get("wiki").unwrap().display_name, "Wiki");
        assert!(cat.get("missing").is_none());
    }

    #[test]
    fn replace_swaps_atomically() {
        let cat = StaticAppCatalog::new(vec![App::new("a", "A")]);
        cat.replace(vec![App::new("b", "B")]);
        assert!(cat.get("a").is_none());
        assert_eq!(cat.get("b").unwrap().display_name, "B");
    }

    #[test]
    fn len_reflects_table_size() {
        let cat = StaticAppCatalog::default();
        assert!(cat.is_empty());
        cat.replace(vec![App::new("a", "A"), App::new("b", "B")]);
        assert_eq!(cat.len(), 2);
        assert!(!cat.is_empty());
    }

    #[test]
    fn snapshot_is_cheap_arc_clone() {
        let cat = StaticAppCatalog::new(vec![App::new("x", "X")]);
        let s1 = cat.snapshot();
        let s2 = cat.snapshot();
        // Two snapshots from the same generation point at
        // the same underlying table.
        assert!(Arc::ptr_eq(&s1, &s2));
    }
}
