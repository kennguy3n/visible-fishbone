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
/// percentage ceiling.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CpuBudget(pub f32);

impl CpuBudget {
    /// The production target for `sng-agent` (0.1 % idle).
    pub const ENDPOINT_DEFAULT: Self = Self(0.1);

    /// The production target for `sng-edge` (2 % idle — the
    /// edge VM is allowed more headroom because it serves
    /// production traffic flows).
    pub const EDGE_DEFAULT: Self = Self(2.0);
}

impl Eq for CpuBudget {}

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
        assert!((CpuBudget::ENDPOINT_DEFAULT.0 - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn edge_defaults_match_documented_targets() {
        assert_eq!(MemoryBudget::EDGE_DEFAULT.0, 256);
        assert!((CpuBudget::EDGE_DEFAULT.0 - 2.0).abs() < f32::EPSILON);
    }
}
