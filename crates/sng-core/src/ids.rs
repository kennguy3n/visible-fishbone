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
id_newtype!(
    /// Ed25519 signing key identifier — used by bundle
    /// verifiers to look up the public key that signed a
    /// particular bundle in the operator-managed key store.
    PolicySigningKeyId
);
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
