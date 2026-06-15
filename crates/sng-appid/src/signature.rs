//! Declarative signature model and its validated, normalised form.
//!
//! The on-disk / on-wire format ([`RawCatalog`] / [`RawApp`]) is a
//! direct serde projection of the JSON catalog. It is deliberately
//! permissive at the type level (everything is a string or a number)
//! so a malformed field produces a typed validation error rather than
//! a deserialisation panic. [`AppSignature::from_raw`] is the single
//! choke point that turns a raw entry into the validated form the
//! matcher compiles, applying every structural invariant exactly once.

use serde::{Deserialize, Serialize};

use crate::error::AppIdError;
use crate::features::{MAX_PROBE_BYTES, Transport};

/// Highest catalog schema version this build understands.
pub const SCHEMA_VERSION: u32 = 1;

/// Raw, untrusted catalog document as parsed straight from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCatalog {
    /// Schema version of the document.
    pub schema_version: u32,
    /// Application entries.
    #[serde(default)]
    pub apps: Vec<RawApp>,
}

/// Raw, untrusted single application entry.
///
/// `#[serde(default)]` on the optional collections lets an author omit
/// a field that does not apply (e.g. a pure-TLS app has no
/// `byte_prefixes`) without writing an empty array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawApp {
    /// Stable application identifier, e.g. `microsoft.teams`.
    pub app_id: String,
    /// Coarse category, e.g. `collaboration`.
    pub category: String,
    /// TLS SNI host suffixes that identify the app.
    #[serde(default)]
    pub sni_suffixes: Vec<String>,
    /// HTTP Host header suffixes that identify the app.
    #[serde(default)]
    pub host_suffixes: Vec<String>,
    /// JA3 fingerprint hashes (lowercase hex) that hint at the app.
    #[serde(default)]
    pub ja3: Vec<String>,
    /// Destination port hints.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Layer-4 transport token (`tcp` / `udp`).
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Leading-byte probes encoded as lowercase hex strings.
    #[serde(default)]
    pub byte_prefixes: Vec<String>,
    /// Base confidence in `[0, 100]`.
    pub confidence: u8,
}

fn default_transport() -> String {
    "tcp".to_string()
}

/// Validated, normalised signature the matcher compiles from a
/// [`RawApp`]. Host suffixes are lowercased and de-dotted; byte probes
/// are decoded and length-bounded; the transport is parsed to the
/// enum; confidence is clamped.
#[derive(Debug, Clone)]
pub struct AppSignature {
    /// Stable application identifier.
    pub app_id: String,
    /// Coarse category.
    pub category: String,
    /// Normalised TLS SNI host suffixes (lowercase, no leading dot or
    /// `*.`).
    pub sni_suffixes: Vec<String>,
    /// Normalised HTTP Host header suffixes.
    pub host_suffixes: Vec<String>,
    /// Lowercased JA3 fingerprint hashes.
    pub ja3: Vec<String>,
    /// Destination port hints.
    pub ports: Vec<u16>,
    /// Parsed layer-4 transport.
    pub transport: Transport,
    /// Decoded leading-byte probes, each at most [`MAX_PROBE_BYTES`].
    pub byte_prefixes: Vec<Vec<u8>>,
    /// Base confidence in `[0, 100]`.
    pub confidence: u8,
}

impl AppSignature {
    /// Validates and normalises a raw entry.
    ///
    /// # Errors
    /// Returns [`AppIdError::Invalid`] if the entry violates a
    /// structural invariant: empty `app_id` / `category`, unknown
    /// transport, malformed hex probe, an over-long probe, or a probe /
    /// suffix set that would never match anything.
    pub fn from_raw(raw: &RawApp) -> Result<Self, AppIdError> {
        let app_id = raw.app_id.trim().to_string();
        if app_id.is_empty() {
            return Err(AppIdError::Invalid("app_id must not be empty".to_string()));
        }
        let category = raw.category.trim().to_string();
        if category.is_empty() {
            return Err(AppIdError::Invalid(format!(
                "app {app_id}: category must not be empty"
            )));
        }
        let transport = Transport::parse(&raw.transport).ok_or_else(|| {
            AppIdError::Invalid(format!(
                "app {app_id}: unknown transport {:?}",
                raw.transport
            ))
        })?;

        let sni_suffixes = normalise_suffixes(&raw.sni_suffixes);
        let host_suffixes = normalise_suffixes(&raw.host_suffixes);
        let ja3 = normalise_ja3(&raw.ja3);

        let mut byte_prefixes = Vec::with_capacity(raw.byte_prefixes.len());
        for hex in &raw.byte_prefixes {
            let bytes = decode_hex(hex).ok_or_else(|| {
                AppIdError::Invalid(format!("app {app_id}: malformed hex probe {hex:?}"))
            })?;
            if bytes.is_empty() {
                return Err(AppIdError::Invalid(format!(
                    "app {app_id}: empty byte probe"
                )));
            }
            if bytes.len() > MAX_PROBE_BYTES {
                return Err(AppIdError::Invalid(format!(
                    "app {app_id}: byte probe of {} bytes exceeds the {MAX_PROBE_BYTES}-byte cap",
                    bytes.len()
                )));
            }
            byte_prefixes.push(bytes);
        }

        // An entry that declares no SNI suffix, no host suffix, no JA3,
        // and no byte probe could only ever match on port — too weak to
        // ever assert an identity. Reject it so the catalog stays
        // meaningful.
        if sni_suffixes.is_empty()
            && host_suffixes.is_empty()
            && ja3.is_empty()
            && byte_prefixes.is_empty()
        {
            return Err(AppIdError::Invalid(format!(
                "app {app_id}: must declare at least one of sni_suffixes, host_suffixes, ja3, or byte_prefixes"
            )));
        }

        Ok(Self {
            app_id,
            category,
            sni_suffixes,
            host_suffixes,
            ja3,
            ports: raw.ports.clone(),
            transport,
            byte_prefixes,
            confidence: raw.confidence.min(100),
        })
    }
}

/// Lowercases, trims, strips a leading wildcard (`*.`) or dot, and
/// de-duplicates a set of host suffixes, dropping empties. The result
/// is sorted for determinism.
fn normalise_suffixes(in_: &[String]) -> Vec<String> {
    let mut out: Vec<String> = in_
        .iter()
        .map(|s| normalise_host(s))
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Normalises a single host / suffix token: trim, lowercase, strip a
/// leading `*.` wildcard and any leading/trailing dots.
#[must_use]
pub fn normalise_host(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    let s = s.strip_prefix("*.").unwrap_or(&s);
    s.trim_matches('.').to_string()
}

fn normalise_ja3(in_: &[String]) -> Vec<String> {
    let mut out: Vec<String> = in_
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Decodes an even-length lowercase/uppercase hex string into bytes,
/// returning `None` on any non-hex character or odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
