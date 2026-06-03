//! HA subsystem error taxonomy.
//!
//! Each variant maps onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and ops
//! dashboards bucket HA failures into the same dotted-lowercase
//! namespace as every other subsystem. HA has no dedicated
//! `ErrorCode` variants of its own (the enum is closed and
//! owned by `sng-core`), so the mapping reuses the closest
//! existing bucket: socket / process / netlink failures map to
//! [`ErrorCode::Io`], MessagePack frame problems map to the
//! wire-encoding / wire-schema buckets, and a peer that cannot
//! be reached maps to [`ErrorCode::ControlPlaneUnreachable`]
//! (the peer edge is, from this instance's point of view, the
//! same class of "remote node I depend on" as the control
//! plane).

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the HA subsystem.
#[derive(Debug, Error)]
pub enum HaError {
    /// A VRRP / state-sync socket operation failed — bind,
    /// multicast join, connect, send, or receive. The VRRP
    /// loop treats a transient socket error as "no
    /// advertisement heard this interval" and keeps running;
    /// a persistent one surfaces through the subsystem health
    /// probe.
    #[error("socket: {0}")]
    Socket(String),

    /// Encoding an outbound frame (VRRP advertisement or a
    /// state-sync record) to MessagePack failed. Pragmatically
    /// unreachable for the well-formed structs this crate emits
    /// — `rmp_serde` does not fail on a serializable Rust value
    /// — but kept distinct from [`Self::Decode`] so a dashboard
    /// filtering on the inbound decode path does not
    /// misclassify an outbound encode fault.
    #[error("encode: {0}")]
    Encode(String),

    /// Decoding an inbound frame failed — truncated read,
    /// corrupt bytes, or a payload whose shape does not match
    /// the expected record. The receiver drops the frame and
    /// keeps the channel open; a decode failure is never fatal
    /// to the sync session on its own.
    #[error("decode: {0}")]
    Decode(String),

    /// A frame's declared length prefix exceeded the configured
    /// maximum. Guards the receiver against a peer (or an
    /// on-wire corruption) that announces a multi-gigabyte
    /// frame and forces an unbounded allocation.
    #[error("frame too large: {len} bytes exceeds max {max}")]
    FrameTooLarge {
        /// Length the peer announced in the frame header.
        len: usize,
        /// Configured ceiling on a single frame.
        max: usize,
    },

    /// The HA peer (the other edge instance) could not be
    /// reached over the state-sync channel — connect timeout,
    /// refused connection, or a mid-session reset. The active
    /// instance does not block on this: state sync is
    /// best-effort and the passive does a full-state pull on
    /// promotion if it fell behind.
    #[error("peer unreachable: {0}")]
    PeerUnreachable(String),

    /// A virtual-IP management command (`ip addr add/del`, the
    /// gratuitous-ARP announcement) failed. On a failed
    /// acquire the instance must NOT advertise itself as Master
    /// — owning the VRRP role without owning the VIP is the
    /// split-brain failure mode this variant exists to surface.
    #[error("vip: {0}")]
    Vip(String),

    /// The operator-supplied HA configuration is internally
    /// inconsistent (e.g. a zero advertisement interval, a
    /// priority of 0 which is reserved for the
    /// release/demotion signal, or an empty interface name).
    /// Surfaced at construction time so a misconfig fails fast
    /// rather than at first failover.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

impl HaError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Socket(_) | Self::Vip(_) => ErrorCode::Io,
            Self::Encode(_) => ErrorCode::WireEncoding,
            Self::Decode(_) | Self::FrameTooLarge { .. } => ErrorCode::WireSchema,
            Self::PeerUnreachable(_) => ErrorCode::ControlPlaneUnreachable,
            Self::InvalidConfig(_) => ErrorCode::ConfigInvalid,
        }
    }
}

/// Convenience alias for fallible HA operations.
pub type HaResult<T> = Result<T, HaError>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn socket_and_vip_map_to_io() {
        assert_eq!(HaError::Socket("bind".into()).code(), ErrorCode::Io);
        assert_eq!(
            HaError::Vip("ip addr add failed".into()).code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn encode_maps_to_wire_encoding_decode_maps_to_wire_schema() {
        assert_eq!(
            HaError::Encode("rmp".into()).code(),
            ErrorCode::WireEncoding
        );
        assert_eq!(HaError::Decode("rmp".into()).code(), ErrorCode::WireSchema);
        assert_eq!(
            HaError::FrameTooLarge {
                len: 1 << 30,
                max: 1 << 20
            }
            .code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn peer_unreachable_maps_to_control_plane_unreachable() {
        assert_eq!(
            HaError::PeerUnreachable("connection refused".into()).code(),
            ErrorCode::ControlPlaneUnreachable
        );
    }

    #[test]
    fn invalid_config_maps_to_config_invalid() {
        assert_eq!(
            HaError::InvalidConfig("zero interval".into()).code(),
            ErrorCode::ConfigInvalid
        );
    }

    #[test]
    fn display_includes_frame_sizes() {
        let s = format!(
            "{}",
            HaError::FrameTooLarge {
                len: 5000,
                max: 1024
            }
        );
        assert!(s.contains("5000"));
        assert!(s.contains("1024"));
    }
}
