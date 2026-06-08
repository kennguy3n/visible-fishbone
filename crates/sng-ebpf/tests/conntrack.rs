// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless
)]

//! End-to-end connection-tracking enhancement tests: per-flow byte
//! counters, flow-duration / long-lived detection, and protocol-anomaly
//! flagging, driven through the public [`FlowState`] API the kernel
//! per-flow map value exposes.

use sng_ebpf::FlowState;
use sng_ebpf::maps::anomaly;

const SEC: u64 = 1_000_000_000;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

#[test]
fn byte_and_packet_counters_accumulate_for_bandwidth_monitoring() {
    let t0 = 10 * SEC;
    let mut fs = FlowState::new(t0, PROTO_TCP);

    // 1000 packets of 1500 bytes over exactly 3 seconds.
    for i in 1..=1_000u64 {
        let now = t0 + (i * 3 * SEC) / 1_000;
        fs.observe(now, 1_500, PROTO_TCP);
    }

    assert_eq!(fs.packets, 1_000);
    assert_eq!(fs.bytes, 1_500_000);
    assert_eq!(fs.duration_ns(), 3 * SEC);
    // 1.5 MB over 3 s = 500 KB/s.
    assert_eq!(fs.bytes_per_sec(), 500_000);
}

#[test]
fn long_lived_connection_detection() {
    let t0 = 5 * SEC;
    let mut fs = FlowState::new(t0, PROTO_TCP);
    fs.observe(t0 + 30, 100, PROTO_TCP); // 30 ns in — short

    assert!(!fs.is_long_lived(60 * SEC));

    // A keepalive an hour later marks the flow long-lived.
    fs.observe(t0 + 3_600 * SEC, 100, PROTO_TCP);
    assert!(fs.is_long_lived(60 * SEC));
    assert_eq!(fs.duration_ns(), 3_600 * SEC);
}

#[test]
fn protocol_anomaly_flagged_when_protocol_changes_mid_stream() {
    let t0 = SEC;
    let mut fs = FlowState::new(t0, PROTO_TCP);
    fs.observe(t0 + 1, 40, PROTO_TCP);
    fs.observe(t0 + 2, 40, PROTO_TCP);
    assert!(!fs.has_anomaly());

    // A packet on the same flow slot suddenly carrying UDP — anomaly.
    fs.observe(t0 + 3, 40, PROTO_UDP);
    assert!(fs.has_anomaly());
    assert!(fs.has_protocol_change());
    assert_eq!(
        fs.anomaly_flags & anomaly::PROTOCOL_CHANGE,
        anomaly::PROTOCOL_CHANGE
    );
    // The original protocol is preserved as the flow's baseline.
    assert_eq!(fs.l4_protocol, PROTO_TCP);
}

#[test]
fn consistent_protocol_never_flags_anomaly() {
    let t0 = SEC;
    let mut fs = FlowState::new(t0, PROTO_UDP);
    for i in 1..=100u64 {
        fs.observe(t0 + i, 64, PROTO_UDP);
    }
    assert!(!fs.has_anomaly());
    assert_eq!(fs.packets, 100);
}

#[test]
fn reordered_packet_does_not_corrupt_duration() {
    let t0 = 100 * SEC;
    let mut fs = FlowState::new(t0, PROTO_TCP);
    fs.observe(t0 + 50 * SEC, 100, PROTO_TCP);
    // A late/reordered packet stamped earlier must not rewind last_seen.
    fs.observe(t0 + 10 * SEC, 100, PROTO_TCP);
    assert_eq!(fs.duration_ns(), 50 * SEC);
    assert_eq!(fs.packets, 2);
}
