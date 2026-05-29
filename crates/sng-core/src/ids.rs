//! Strongly-typed identifier newtypes.
//!
//! Every cross-boundary id in the SNG control plane is a UUID, but
//! UUIDs by themselves do not encode WHICH boundary they cross —
//! it is easy to pass a `DeviceId` where a `TenantId` is required,
//! and the compiler will not stop you. The newtype wrappers below
//! make that mistake a type error. They also keep an
//! `id.tenant_id()`-style API consistent across the workspace, and
//! give us one place to add transport-format coercions
//! (msgpack tags, hex+dash human format, base32 short ids) when
//! they are needed.
//!
//! Every newtype:
//!
//! * is `#[repr(transparent)]` over `uuid::Uuid` so the in-memory
//!   layout is identical to the inner type and no FFI shim is
//!   needed when crossing to the C / Go side;
//! * derives `Copy + Clone + Debug + PartialEq + Eq + Hash` for
//!   ergonomic use as map keys and in test assertions;
//! * derives `Serialize + Deserialize` so the wire format matches
//!   the Go side byte-for-byte;
//! * implements `Display` so the canonical hyphenated 36-character
//!   string form is what shows up in log lines and error messages;
//! * has a `nil()` associated constructor for the "uninitialised"
//!   sentinel (used by validators that check for `id == nil`) and
//!   a `new_v4()` random-id constructor for tests.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Generates a strongly-typed UUID newtype with the standard
/// derive set, `nil`/`new_v4` constructors, `Display`/`FromStr`
/// impls, and `From<Uuid>` / `Into<Uuid>` coercions.
///
/// The macro is internal to this module; consumers see only the
/// generated types.
macro_rules! id_newtype {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(
            Copy,
            Clone,
            Debug,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
        )]
        #[repr(transparent)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps a raw UUID.
            #[must_use]
            pub const fn from_uuid(u: Uuid) -> Self {
                Self(u)
            }

            /// Unwraps to the underlying UUID.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Borrows the underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// The all-zero (nil) UUID. Use as the
            /// "uninitialised" sentinel for validator checks
            /// such as `if id == TenantId::nil() { error }`.
            #[must_use]
            pub const fn nil() -> Self {
                Self(Uuid::nil())
            }

            /// Generates a random version-4 UUID. Intended for
            /// tests and for ephemeral ids the control plane
            /// does not persist. Use a v7 id (time-ordered) for
            /// anything that lands in a Postgres primary key.
            #[must_use]
            pub fn new_v4() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns true if this id is the nil sentinel.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0.is_nil()
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s).map(Self)
            }
        }
    };
}

id_newtype!(
    /// Tenant identifier — the partition every other id is
    /// scoped under. Postgres RLS policies use the equivalent
    /// `current_setting('app.tenant_id')::uuid` predicate.
    TenantId
);
id_newtype!(
    /// Endpoint device identifier. One device may belong to many
    /// users but only one tenant.
    DeviceId
);
id_newtype!(
    /// Site identifier — a logical grouping of edge VMs and
    /// endpoints (typically a branch office or cloud region).
    SiteId
);
id_newtype!(
    /// Policy bundle identifier — the compiled, signed artefact
    /// the control plane distributes to edge VMs / endpoints.
    PolicyBundleId
);
id_newtype!(
    /// Policy graph identifier — the typed source-of-truth
    /// policy graph the control plane compiles bundles from.
    PolicyGraphId
);
/// Ed25519 signing key identifier — used by bundle verifiers
/// to look up the public key that signed a particular bundle in
/// the operator-managed key store.
///
/// Unlike the UUID-shaped identifiers above, this one is a short
/// string. The Go control plane derives it as the first 16 hex
/// characters of `SHA-256(public_key)` for file-backed signers
/// or the first 8 bytes of a fresh UUID v4 for KMS-backed
/// signers — both shapes land in the same 16-char form on purpose
/// so receivers (this module) treat them identically. See
/// `internal/service/policy/keys.go::newKeyID` and
/// `internal/service/policy/service.go::deriveKeyID`. Stored as
/// a `String` rather than `[u8; 8]` so future identifier shapes
/// (longer key ids, non-hex alphabets, KMS ARNs, etc.) do not
/// require a wire-format break.
/// Wire shape: a single MessagePack / JSON string. The custom
/// [`Deserialize`] impl below enforces [`Self::MAX_LEN`] *at the
/// wire boundary*, not just on the constructor. Without that, the
/// auto-derived `#[serde(transparent)]` impl would happily accept
/// any-length string from the network and only the downstream
/// trust-store lookup would notice — which is fine for security
/// (the lookup will miss) but is a defence-in-depth gap that lets
/// a misbehaving producer push arbitrarily large key-id strings
/// through the bundle path and into log lines / dashboards.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PolicySigningKeyId(String);

impl PolicySigningKeyId {
    /// Maximum accepted length. Generous headroom over the
    /// canonical 16-char form so KMS-backed signers can adopt
    /// longer identifiers without forcing a wire bump. Wire
    /// values larger than this are rejected at parse time.
    pub const MAX_LEN: usize = 64;

    /// Wraps a raw string id. Returns an error if the id is
    /// empty or longer than [`Self::MAX_LEN`]. The empty id is
    /// reserved as the "no signer" sentinel returned by
    /// `EphemeralSigner` on the Go side — that case must use
    /// [`Self::ephemeral`] explicitly rather than passing the
    /// empty string here.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidPolicySigningKeyId> {
        let v = value.into();
        if v.is_empty() {
            return Err(InvalidPolicySigningKeyId::Empty);
        }
        if v.len() > Self::MAX_LEN {
            return Err(InvalidPolicySigningKeyId::TooLong {
                got: v.len(),
                max: Self::MAX_LEN,
            });
        }
        Ok(Self(v))
    }

    /// The sentinel id used by ephemeral signers on the Go side.
    /// Receivers MUST reject bundles carrying this id — there is
    /// no key to verify against. Provided as a constructor so the
    /// rejection path can be tested without bypassing
    /// [`Self::new`]'s validation.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self(String::new())
    }

    /// Returns true if this is the [`Self::ephemeral`] sentinel.
    #[must_use]
    pub fn is_ephemeral(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrows the underlying id string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicySigningKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PolicySigningKeyId {
    type Err = InvalidPolicySigningKeyId;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl<'de> Deserialize<'de> for PolicySigningKeyId {
    /// Enforces the [`Self::MAX_LEN`] cap on the wire so an
    /// attacker / misbehaving producer cannot push arbitrarily
    /// long key-id strings through the bundle path.
    ///
    /// The empty string is *accepted* here because it is the
    /// canonical ephemeral-signer sentinel that the Go side
    /// produces for unsigned bundles — receivers reject those
    /// later in [`crate::policy::PolicyVerifier::verify`] via
    /// [`Self::is_ephemeral`], so the deserialiser would only get
    /// in the way by collapsing the two failure modes
    /// ("ephemeral signer used" vs. "wire id too long") into one.
    fn deserialize<D: serde::de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(de)?;
        if raw.is_empty() {
            return Ok(Self::ephemeral());
        }
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Error returned by [`PolicySigningKeyId::new`] /
/// [`PolicySigningKeyId::from_str`] when the candidate id fails
/// shape validation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidPolicySigningKeyId {
    /// The empty string is reserved for the ephemeral sentinel —
    /// use [`PolicySigningKeyId::ephemeral`] explicitly.
    #[error("policy signing key id must be non-empty")]
    Empty,
    /// The candidate id exceeded [`PolicySigningKeyId::MAX_LEN`].
    #[error("policy signing key id is {got} chars, max {max}")]
    TooLong { got: usize, max: usize },
}

id_newtype!(
    /// Enrolment claim token identifier. The plaintext claim
    /// token is hashed at the boundary; only the identifier and
    /// the hash are stored.
    ClaimTokenId
);
id_newtype!(
    /// Per-event identifier. Used by the telemetry pipeline for
    /// dedup over a sliding window.
    EventId
);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn nil_constructors_return_zero_uuid() {
        assert!(TenantId::nil().is_nil());
        assert_eq!(TenantId::nil().into_uuid(), Uuid::nil());
        assert!(DeviceId::nil().is_nil());
        assert!(EventId::nil().is_nil());
    }

    #[test]
    fn new_v4_is_random_and_not_nil() {
        let a = TenantId::new_v4();
        let b = TenantId::new_v4();
        assert!(!a.is_nil());
        assert_ne!(a, b);
    }

    #[test]
    fn from_uuid_round_trip_preserves_bytes() {
        let raw = Uuid::new_v4();
        let id = TenantId::from_uuid(raw);
        assert_eq!(id.into_uuid(), raw);
        let back: Uuid = id.into();
        assert_eq!(back, raw);
    }

    #[test]
    fn display_matches_uuid_hyphenated_form() {
        let raw = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid uuid");
        let id = SiteId::from_uuid(raw);
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn from_str_parses_canonical_hyphenated_form() {
        let parsed: PolicyBundleId = "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("valid uuid");
        assert_eq!(
            parsed.into_uuid(),
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap_or_else(|_| {
                Uuid::nil() // unreachable; placates clippy::unwrap_used
            })
        );
    }

    #[test]
    fn from_str_rejects_garbage() {
        let r: Result<DeviceId, _> = "not-a-uuid".parse();
        assert!(r.is_err());
    }

    #[test]
    fn json_round_trip_is_transparent() {
        let raw = Uuid::new_v4();
        let id = DeviceId::from_uuid(raw);
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, format!("\"{raw}\""));
        let back: DeviceId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
    }

    #[test]
    fn policy_signing_key_id_deserialize_rejects_too_long() {
        // The deserialise path must enforce MAX_LEN at the wire
        // boundary so a misbehaving producer cannot push a 1 MB
        // "key id" into log lines / dashboards. Build a JSON
        // string that's deliberately longer than the cap.
        let too_long = "a".repeat(PolicySigningKeyId::MAX_LEN + 1);
        let json = format!("\"{too_long}\"");
        let err: Result<PolicySigningKeyId, _> = serde_json::from_str(&json);
        assert!(err.is_err(), "deserialise of over-MAX_LEN must fail");
    }

    #[test]
    fn policy_signing_key_id_deserialize_accepts_at_max_len() {
        // Exactly MAX_LEN is still valid (the constructor uses
        // `len() > MAX_LEN`, not `>=`). This pins the boundary so
        // a future refactor of the constructor doesn't silently
        // narrow what wire keys deserialise.
        let at_max = "a".repeat(PolicySigningKeyId::MAX_LEN);
        let json = format!("\"{at_max}\"");
        let id: PolicySigningKeyId = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(id.as_str(), at_max);
    }

    #[test]
    fn policy_signing_key_id_deserialize_accepts_empty_as_ephemeral() {
        // The empty string is the canonical ephemeral-signer
        // sentinel on the Go side and must round-trip through
        // serde rather than being rejected at the wire boundary.
        // Downstream verification (`PolicyVerifier::verify`) is
        // responsible for rejecting bundles signed by an
        // ephemeral signer.
        let id: PolicySigningKeyId = serde_json::from_str("\"\"").expect("deserialise");
        assert!(id.is_ephemeral());
    }

    #[test]
    fn policy_signing_key_id_serde_round_trip_short_form() {
        let id = PolicySigningKeyId::new("abc123").expect("valid");
        let json = serde_json::to_string(&id).expect("serialise");
        assert_eq!(json, "\"abc123\"");
        let back: PolicySigningKeyId = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, id);
    }

    #[test]
    fn newtypes_are_distinct_at_the_type_level() {
        // This test is a compile-time check that the workspace
        // boundary enforced by these newtypes is real: the
        // function only accepts TenantId, so passing a
        // DeviceId.into_uuid() through it would fail to compile
        // without the explicit From<Uuid> wrap. We re-wrap here
        // to demonstrate the conversion is explicit, not
        // automatic — the safety property is "the compiler
        // refuses an implicit DeviceId → TenantId coercion",
        // which would surface as a build break if someone
        // removed the newtype and aliased the types instead.
        fn takes_tenant(_t: TenantId) {}
        let dev = DeviceId::new_v4();
        let tenant: TenantId = dev.into_uuid().into();
        takes_tenant(tenant);
    }
}
