//! The validated signature catalog: a parsed, invariant-checked set of
//! [`AppSignature`]s plus the embedded compile-time baseline.

use std::sync::OnceLock;

use crate::error::AppIdError;
use crate::signature::{AppSignature, RawCatalog, SCHEMA_VERSION};

/// The embedded seed catalog, compiled into the binary. This is the
/// data plane's baseline: it identifies a few hundred well-known apps
/// even before the control plane pushes a signed bundle, so a fresh
/// edge with no network to the control plane still does meaningful
/// app-id (graceful degradation / no-ops).
const EMBEDDED_CATALOG_JSON: &str = include_str!("../data/catalog.json");

/// A validated catalog of application signatures.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    apps: Vec<AppSignature>,
}

impl Catalog {
    /// Parses and validates a JSON catalog document.
    ///
    /// # Errors
    /// - [`AppIdError::Malformed`] if the bytes are not valid JSON in
    ///   the catalog shape.
    /// - [`AppIdError::UnsupportedSchema`] if the document declares a
    ///   schema version newer than this build supports.
    /// - [`AppIdError::Invalid`] if any entry violates a structural
    ///   invariant or two entries share an `app_id`.
    pub fn from_json(doc: &str) -> Result<Self, AppIdError> {
        let raw: RawCatalog =
            serde_json::from_str(doc).map_err(|e| AppIdError::Malformed(e.to_string()))?;
        if raw.schema_version > SCHEMA_VERSION {
            return Err(AppIdError::UnsupportedSchema(raw.schema_version));
        }
        let mut apps = Vec::with_capacity(raw.apps.len());
        for entry in &raw.apps {
            apps.push(AppSignature::from_raw(entry)?);
        }
        Self::from_signatures(apps)
    }

    /// Builds a catalog from already-validated signatures, enforcing
    /// the cross-entry invariant that `app_id`s are unique. Entries are
    /// sorted by `app_id` so the compiled matcher and any serialised
    /// projection are deterministic.
    ///
    /// # Errors
    /// Returns [`AppIdError::Invalid`] if two signatures share an
    /// `app_id`.
    pub fn from_signatures(mut apps: Vec<AppSignature>) -> Result<Self, AppIdError> {
        apps.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        for pair in apps.windows(2) {
            if pair[0].app_id == pair[1].app_id {
                return Err(AppIdError::Invalid(format!(
                    "duplicate app_id {:?}",
                    pair[0].app_id
                )));
            }
        }
        Ok(Self { apps })
    }

    /// Parses the embedded seed catalog. Used by tests to assert the
    /// shipped baseline is well-formed; production code uses
    /// [`Catalog::builtin`], which never panics.
    ///
    /// # Errors
    /// Propagates any parse / validation error from the embedded JSON.
    pub fn parse_embedded() -> Result<Self, AppIdError> {
        Self::from_json(EMBEDDED_CATALOG_JSON)
    }

    /// Returns the process-wide embedded baseline catalog, parsed once.
    ///
    /// If the embedded JSON ever failed to parse (it cannot in a tested
    /// build — [`Catalog::parse_embedded`] is asserted in CI) this
    /// degrades to an empty catalog rather than panicking, so a bug in
    /// the seed can never take down the data path.
    #[must_use]
    pub fn builtin() -> &'static Catalog {
        static BUILTIN: OnceLock<Catalog> = OnceLock::new();
        BUILTIN.get_or_init(|| Self::parse_embedded().unwrap_or_default())
    }

    /// The validated signatures, sorted by `app_id`.
    #[must_use]
    pub fn signatures(&self) -> &[AppSignature] {
        &self.apps
    }

    /// Number of application signatures in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.apps.len()
    }

    /// Whether the catalog has no signatures.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
    }
}
