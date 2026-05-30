//! Resource budget primitives.
//!
//! The endpoint agent runs under tight resource constraints —
//! sub-15 MB resident memory, sub-0.1 % idle CPU. Every PAL
//! subsystem reports its own consumption through
//! [`ResourceBudgetReport`] so the supervisor can roll up a
//! workspace-wide budget posture for the operator dashboard and
//! warn / shed load before a subsystem starves the rest.

use serde::{Deserialize, Serialize};

/// Memory budget for the endpoint agent. The wrapped value is
/// the ceiling in megabytes; the agent's resident memory should
/// stay under it during steady-state operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryBudget(pub u32);

impl MemoryBudget {
    /// The production target for `sng-agent` (15 MB).
    pub const ENDPOINT_DEFAULT: Self = Self(15);

    /// The production target for `sng-edge` (256 MB — the edge
    /// VM is allowed a much larger share because it terminates
    /// actual traffic and runs Suricata / Envoy).
    pub const EDGE_DEFAULT: Self = Self(256);

    /// Bytes form of the ceiling.
    #[must_use]
    pub const fn as_bytes(self) -> u64 {
        (self.0 as u64) * 1024 * 1024
    }
}

/// CPU budget. Wrapped value is the steady-state idle-CPU
/// ceiling in **milli-percent** units (i.e. thousandths of a
/// percentage point). `100` is `0.100 %`, `2_000` is `2.000 %`.
///
/// Stored as an integer rather than `f32` so equality, hashing,
/// and ordering are exact (no NaN / sub-normal hazards) and so
/// the JSON / MessagePack on-wire form is unambiguous. The
/// human-readable percentage is reconstituted on demand via
/// [`Self::as_percent`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CpuBudget {
    /// Idle-CPU ceiling in milli-percent (1/1000 of a percent).
    pub milli_percent: u32,
}

impl CpuBudget {
    /// The production target for `sng-agent` (0.100 % idle).
    pub const ENDPOINT_DEFAULT: Self = Self { milli_percent: 100 };

    /// The production target for `sng-edge` (2.000 % idle — the
    /// edge VM is allowed more headroom because it serves
    /// production traffic flows).
    pub const EDGE_DEFAULT: Self = Self {
        milli_percent: 2_000,
    };

    /// Construct from a milli-percent value.
    #[must_use]
    pub const fn from_milli_percent(milli_percent: u32) -> Self {
        Self { milli_percent }
    }

    /// Human-readable percentage form (e.g. `0.1` for the
    /// endpoint default). Uses `f64` for the division so the
    /// rounding error against `milli_percent / 1000` is at most
    /// one ulp of `f32`.
    #[must_use]
    pub fn as_percent(self) -> f32 {
        // u32 -> f64 is lossless; the final narrow to f32 only
        // loses precision at percentages far above any
        // realistically configured CPU budget.
        #[allow(clippy::cast_possible_truncation)]
        let pct = (f64::from(self.milli_percent) / 1000.0) as f32;
        pct
    }
}

/// Per-subsystem resource-consumption report. Aggregated by the
/// supervisor into a workspace-wide posture snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudgetReport {
    /// Subsystem name (stable, lowercase).
    pub name: String,
    /// Resident memory consumption, bytes.
    pub resident_bytes: u64,
    /// Cumulative CPU time consumed, microseconds.
    pub cpu_user_micros: u64,
    /// Cumulative kernel CPU time consumed, microseconds.
    pub cpu_kernel_micros: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_defaults_match_documented_targets() {
        assert_eq!(MemoryBudget::ENDPOINT_DEFAULT.0, 15);
        // ResourceBudget on the Go side defaults match; this is
        // the wire contract between the two sides.
        assert_eq!(MemoryBudget::ENDPOINT_DEFAULT.as_bytes(), 15 * 1024 * 1024);
        assert_eq!(CpuBudget::ENDPOINT_DEFAULT.milli_percent, 100);
        assert!((CpuBudget::ENDPOINT_DEFAULT.as_percent() - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn edge_defaults_match_documented_targets() {
        assert_eq!(MemoryBudget::EDGE_DEFAULT.0, 256);
        assert_eq!(CpuBudget::EDGE_DEFAULT.milli_percent, 2_000);
        assert!((CpuBudget::EDGE_DEFAULT.as_percent() - 2.0).abs() < f32::EPSILON);
    }

    #[test]
    fn cpu_budget_supports_value_equality_and_hashing() {
        // Switching CpuBudget off f32 means it now satisfies
        // Eq + Hash + Ord without the soundness hazards of an
        // f32-backed manual Eq. Verify the derived traits behave.
        use std::collections::HashSet;
        let a = CpuBudget::from_milli_percent(100);
        let b = CpuBudget::ENDPOINT_DEFAULT;
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
        assert!(CpuBudget::ENDPOINT_DEFAULT < CpuBudget::EDGE_DEFAULT);
    }

    #[test]
    fn cpu_budget_round_trips_through_serde_json() {
        // Wire form is the integer milli_percent field, which is
        // what makes the type unambiguous on the JSON / msgpack
        // boundary. Encoding then decoding must yield the same
        // bit pattern.
        let original = CpuBudget::ENDPOINT_DEFAULT;
        let json = serde_json::to_string(&original).expect("encode");
        let decoded: CpuBudget = serde_json::from_str(&json).expect("decode");
        assert_eq!(original, decoded);
    }
}
