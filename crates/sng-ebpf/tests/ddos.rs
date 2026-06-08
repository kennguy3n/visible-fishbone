// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding. The crate-level lib.rs allow only fires for
// `#[cfg(test)]` units inside the library crate; integration
// test files in `tests/` are separate crates so we repeat the
// same allow list at the file top.
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

//! End-to-end XDP DDoS-mitigation tests driving the public API the way
//! the edge does: build a [`DdosConfig`], install it through the
//! [`XdpControlPlane`] (the `NoopLoader` map model — no kernel needed,
//! see `crates/sng-ebpf/README.md`), and drive packets through a
//! [`DdosMitigator`] built from the same config.

use std::net::{IpAddr, Ipv4Addr};

use sng_ebpf::{
    DdosConfig, DdosMitigator, DropReason, GeoIpBlocklist, GeoIpEntry, GeoIpTable, PacketMeta,
    RateLimit, XdpAction, XdpControlPlane,
    ddos::{PROTO_TCP, PROTO_UDP, tcp_flags},
};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

const SEC: u64 = 1_000_000_000;

fn tenant_config() -> DdosConfig {
    DdosConfig {
        // 1000-SYN burst, 500/s sustained per source.
        syn: Some(RateLimit::new(1_000, 500).unwrap()),
        // 5000-datagram burst, 2000/s sustained per source.
        udp: Some(RateLimit::new(5_000, 2_000).unwrap()),
        geoip: GeoIpTable::new(vec![
            GeoIpEntry::new("203.0.113.0/24".parse().unwrap(), *b"CN"),
            GeoIpEntry::new("198.51.100.0/24".parse().unwrap(), *b"RU"),
            GeoIpEntry::new("192.0.2.0/24".parse().unwrap(), *b"US"),
        ]),
        // This tenant blocks CN and RU; US is allowed.
        blocklist: GeoIpBlocklist::new([*b"CN", *b"RU"]),
    }
}

fn syn_from(src: IpAddr) -> PacketMeta {
    PacketMeta {
        src_ip: src,
        dst_ip: v4(10, 0, 0, 1),
        src_port: 40000,
        dst_port: 443,
        protocol: PROTO_TCP,
        tcp_flags: tcp_flags::SYN,
        len: 64,
    }
}

fn udp_from(src: IpAddr) -> PacketMeta {
    PacketMeta {
        src_ip: src,
        dst_ip: v4(10, 0, 0, 1),
        src_port: 40000,
        dst_port: 53,
        protocol: PROTO_UDP,
        tcp_flags: 0,
        len: 512,
    }
}

#[test]
fn config_installs_through_control_plane() {
    let cp = XdpControlPlane::in_memory();
    cp.load_and_attach("eth0", sng_ebpf::XdpMode::Skb).unwrap();
    cp.install_ddos(tenant_config()).unwrap();

    let stats = cp.stats();
    assert!(stats.ddos_installed);
    assert_eq!(stats.geoip_entries, 3);
    assert_eq!(stats.update_failures, 0);
}

#[test]
fn syn_flood_from_one_source_is_dropped_after_burst() {
    let mut m = DdosMitigator::new(tenant_config());
    let attacker = v4(45, 33, 32, 156);

    // The first 1000 SYNs (the burst capacity) pass; everything beyond
    // the budget within the same instant is dropped as a flood.
    let mut passed = 0u32;
    let mut dropped = 0u32;
    for _ in 0..10_000 {
        match m.evaluate(&syn_from(attacker), 0).reason {
            DropReason::Allowed => passed += 1,
            DropReason::SynFlood => dropped += 1,
            other => panic!("unexpected reason {other:?}"),
        }
    }
    assert_eq!(passed, 1_000, "burst capacity should pass");
    assert_eq!(dropped, 9_000, "the rest is flood-dropped");
    assert_eq!(m.stats().syn_dropped, 9_000);
}

#[test]
fn legitimate_low_rate_source_is_never_dropped() {
    let mut m = DdosMitigator::new(tenant_config());
    let client = v4(8, 8, 8, 8); // not in the GeoIP DB → no country block

    // One SYN every 100 ms = 10/s, far under the 500/s sustained budget.
    for i in 0..1_000u64 {
        let now = i * (SEC / 10);
        assert_eq!(
            m.evaluate(&syn_from(client), now).reason,
            DropReason::Allowed
        );
    }
    assert_eq!(m.stats().syn_dropped, 0);
}

#[test]
fn sustained_rate_refills_between_bursts() {
    let mut m = DdosMitigator::new(tenant_config());
    let src = v4(8, 8, 4, 4);

    // Drain the 1000-token burst at t=0.
    for _ in 0..1_000 {
        assert_eq!(m.evaluate(&syn_from(src), 0).reason, DropReason::Allowed);
    }
    assert_eq!(m.evaluate(&syn_from(src), 0).reason, DropReason::SynFlood);

    // After 1 second at 500/s sustained, ~500 tokens are back.
    let t = SEC;
    let mut passed = 0u32;
    for _ in 0..1_000 {
        if m.evaluate(&syn_from(src), t).reason == DropReason::Allowed {
            passed += 1;
        }
    }
    assert_eq!(passed, 500, "one second of refill at 500/s");
}

#[test]
fn geoip_blocks_configured_countries_only() {
    let mut m = DdosMitigator::new(tenant_config());

    // CN and RU are blocked outright, regardless of rate.
    let v = m.evaluate(&syn_from(v4(203, 0, 113, 9)), 0);
    assert_eq!(v.action, XdpAction::Drop);
    assert_eq!(v.reason, DropReason::GeoBlocked);

    let v = m.evaluate(&udp_from(v4(198, 51, 100, 9)), 0);
    assert_eq!(v.reason, DropReason::GeoBlocked);

    // US is in the DB but not on this tenant's blocklist → allowed.
    let v = m.evaluate(&syn_from(v4(192, 0, 2, 9)), 0);
    assert_eq!(v.reason, DropReason::Allowed);

    assert_eq!(m.stats().geo_dropped, 2);
}

#[test]
fn geoip_blocklist_is_per_tenant() {
    // Same GeoIP database, two tenants with different blocklists.
    let db = GeoIpTable::new(vec![GeoIpEntry::new(
        "203.0.113.0/24".parse().unwrap(),
        *b"CN",
    )]);
    let strict = DdosConfig {
        geoip: db.clone(),
        blocklist: GeoIpBlocklist::new([*b"CN"]),
        ..DdosConfig::default()
    };
    let lenient = DdosConfig {
        geoip: db,
        blocklist: GeoIpBlocklist::default(), // blocks nothing
        ..DdosConfig::default()
    };

    let mut strict_m = DdosMitigator::new(strict);
    let mut lenient_m = DdosMitigator::new(lenient);
    let cn = syn_from(v4(203, 0, 113, 1));

    assert_eq!(strict_m.evaluate(&cn, 0).reason, DropReason::GeoBlocked);
    assert_eq!(lenient_m.evaluate(&cn, 0).reason, DropReason::Allowed);
}

#[test]
fn udp_flood_is_independent_of_syn_flood() {
    let mut m = DdosMitigator::new(tenant_config());
    let src = v4(8, 8, 8, 1);

    // Drain the UDP budget (5000) entirely; SYN budget is untouched.
    for _ in 0..5_000 {
        assert_eq!(m.evaluate(&udp_from(src), 0).reason, DropReason::Allowed);
    }
    assert_eq!(m.evaluate(&udp_from(src), 0).reason, DropReason::UdpFlood);

    // The same source can still open TCP connections — separate bucket.
    assert_eq!(m.evaluate(&syn_from(src), 0).reason, DropReason::Allowed);
}

#[test]
fn distributed_sources_each_get_their_own_budget() {
    let mut m = DdosMitigator::new(tenant_config());
    // 200 distinct sources each send exactly their burst — all allowed.
    for host in 0..200u8 {
        let src = v4(100, 64, 0, host);
        for _ in 0..1_000 {
            assert_eq!(m.evaluate(&syn_from(src), 0).reason, DropReason::Allowed);
        }
    }
    assert_eq!(m.stats().syn_dropped, 0);
    assert_eq!(m.syn_tracked(), 200);

    // The 201st SYN from any one of them now exceeds that source's budget.
    assert_eq!(
        m.evaluate(&syn_from(v4(100, 64, 0, 0)), 0).reason,
        DropReason::SynFlood
    );
}
