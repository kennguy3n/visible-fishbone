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
    clippy::cast_lossless,
    clippy::float_cmp
)]

//! End-to-end integration tests for the `sng-agent` supervisor.
//!
//! These cover the seams the per-subsystem unit tests cannot:
//! the [`build_agent`] composition pass, PAL backend
//! validation, and the desired-tunnel watch channel as
//! observed end-to-end through the [`PalTunnelSubsystem`]
//! adapter. They deliberately don't drive `supervisor.run()`
//! end-to-end (that requires either a live control-plane
//! mock or a `from_parts`-style test rig that the supervisor
//! builder does not currently expose); composition + the
//! tunnel reconcile loop are enough to pin down the binary
//! crate's wiring contract without duplicating the per-crate
//! unit tests already living in `crates/sng-{pal,ztna,...}`.

use clap::Parser;
use ipnet::IpNet;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use sng_agent::config::{
    AgentConfig, CaptureConfig, CommsConfig, DlpConfig, IdentityConfig, PolicyConfig,
    PostureConfig, SupervisorConfig, TelemetryConfig, TunnelConfig as TunnelCadenceConfig,
    ZtnaConfig,
};
use sng_agent::{AgentBuildError, Cli, PalBackend, build_agent};
use sng_core::ids::{DeviceId, TenantId};
use sng_pal::tunnel::TunnelConfig as PalTunnelConfig;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

/// Mint a self-signed Ed25519 cert + matching key in PEM form.
/// rcgen is already pulled in via `sng-comms`'s own test
/// suite — we depend on it here as a dev-dependency for the
/// same purpose.
fn mint_identity_pem() -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
    let mut params =
        CertificateParams::new(vec!["agent-integration-test".into()]).expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "agent-integration-test");
    let cert = params.self_signed(&key).expect("cert");
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

/// Materialise a freshly-minted identity onto disk and
/// return the (cert_path, key_path, tempdir_holder) tuple.
/// The tempdir handle must outlive the returned paths.
fn write_identity_to_disk() -> (PathBuf, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    let (cert_pem, key_pem) = mint_identity_pem();
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");
    (cert_path, key_path, dir)
}

/// Build a syntactically valid agent config rooted at a
/// real on-disk PEM pair. The returned `_dir` is the
/// `TempDir` holding the PEM files; it must outlive the
/// returned `AgentConfig`.
fn fresh_config() -> (AgentConfig, TempDir) {
    let (cert_path, key_path, dir) = write_identity_to_disk();
    let cfg = AgentConfig {
        identity: IdentityConfig {
            tenant_id: TenantId::from_uuid(Uuid::from_u128(0xA11C_E001)),
            device_id: DeviceId::from_uuid(Uuid::from_u128(0xDEAD_BEEF)),
            site_id: None,
        },
        comms: CommsConfig {
            endpoint: "control.test:443".into(),
            server_name: None,
            client_cert: cert_path,
            client_key: key_path,
            trust_roots: None,
            backoff_initial: Duration::from_millis(250),
            backoff_max: Duration::from_secs(30),
        },
        policy: PolicyConfig::default(),
        telemetry: TelemetryConfig::default(),
        ztna: ZtnaConfig::default(),
        capture: CaptureConfig::default(),
        posture: PostureConfig::default(),
        tunnel: TunnelCadenceConfig {
            // Fast cadence so the integration test exercises
            // the reconcile loop without sleeping the test
            // process for seconds.
            reconcile_interval: Duration::from_millis(20),
        },
        dlp: DlpConfig::default(),
        supervisor: SupervisorConfig::default(),
    };
    (cfg, dir)
}

fn fresh_cli() -> Cli {
    // Use the binary's actual clap parser so the `default_value_t`
    // attributes are honoured exactly as they would be at
    // runtime. `--config` is required by the schema so we
    // hand it a non-existent placeholder; `build_agent` itself
    // never reads it (the caller already loaded the config).
    Cli::try_parse_from(["sng-agent", "--config", "/dev/null"]).expect("parse")
}

#[tokio::test(flavor = "multi_thread")]
async fn build_agent_assembles_seven_subsystems_with_in_memory_pal() {
    let cli = fresh_cli();
    let (cfg, _dir) = fresh_config();
    let built = build_agent(&cli, &cfg).expect("build_agent");

    // Strong handles for every adapter so a future refactor
    // that drops one would force a compile / test failure
    // here rather than silently regressing the wiring.
    assert_eq!(built.telemetry.name_for_debug(), "telemetry");
    assert_eq!(built.comms.name_for_debug(), "comms");
    assert_eq!(built.policy_eval.name_for_debug(), "policy_eval");
    assert_eq!(built.ztna.name_for_debug(), "ztna");
    assert_eq!(built.pal_capture.name_for_debug(), "pal_capture");
    assert_eq!(built.pal_posture.name_for_debug(), "pal_posture");
    assert_eq!(built.pal_tunnel.name_for_debug(), "pal_tunnel");

    // The desired-tunnel sender starts empty so the
    // reconciler boots into a zero-tunnel steady state.
    assert!(built.desired_tunnels_tx.borrow().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn build_agent_rejects_unified_native_pal_backend_up_front() {
    let cli = Cli::try_parse_from([
        "sng-agent",
        "--config",
        "/dev/null",
        "--pal-backend",
        "native",
    ])
    .expect("parse");
    let (cfg, _dir) = fresh_config();
    let err = build_agent(&cli, &cfg).unwrap_err();
    let selector = match err {
        AgentBuildError::UnsupportedPalBackend { selector, backend } => {
            assert_eq!(backend, PalBackend::Native);
            selector
        }
        other => panic!("expected UnsupportedPalBackend, got {other:?}"),
    };
    // The capture adapter is checked first, so a unified
    // `--pal-backend native` surfaces as a capture rejection.
    assert_eq!(selector, "capture");
}

#[tokio::test(flavor = "multi_thread")]
async fn build_agent_rejects_per_subsystem_native_override() {
    // Pin posture to native explicitly; capture + tunnel
    // remain on the default (InMemory) selector.
    let cli = Cli::try_parse_from([
        "sng-agent",
        "--config",
        "/dev/null",
        "--posture-backend",
        "native",
    ])
    .expect("parse");
    let (cfg, _dir) = fresh_config();
    let err = build_agent(&cli, &cfg).unwrap_err();
    match err {
        AgentBuildError::UnsupportedPalBackend { selector, backend } => {
            assert_eq!(selector, "posture");
            assert_eq!(backend, PalBackend::Native);
        }
        other => panic!("expected UnsupportedPalBackend, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn desired_tunnels_publisher_drives_pal_tunnel_reconcile() {
    use sng_core::{ShutdownTrigger, Subsystem};
    let cli = fresh_cli();
    let (cfg, _dir) = fresh_config();
    let built = build_agent(&cli, &cfg).expect("build_agent");

    // We don't `supervisor.run()` here because that would
    // require mocking the control plane (the comms subsystem
    // would otherwise dial a live endpoint). Instead drive
    // the tunnel adapter standalone — the supervisor's job is
    // to fan a shutdown signal through every adapter, and
    // that contract is exercised in the per-crate
    // `sng-core::supervisor` tests.
    let pal_tunnel = Arc::clone(&built.pal_tunnel);
    let (trigger, signal) = ShutdownTrigger::new();
    let handle = pal_tunnel.start(signal).await.expect("pal_tunnel start");

    // Push a single desired tunnel through the supervisor's
    // own sender.
    let desired = vec![PalTunnelConfig {
        id: "control-plane".into(),
        endpoint: "10.0.0.1:51820".parse().expect("addr"),
        peer_public_key_b64: "A".repeat(43) + "=",
        keepalive_seconds: 25,
        allowed_ips: vec![IpNet::from_str("0.0.0.0/0").expect("net")],
    }];
    built
        .desired_tunnels_tx
        .send(desired)
        .expect("publish desired tunnel set");

    // Spin until the reconciler observes ≥1 successful
    // start, or fail under a generous timeout.
    let stats = pal_tunnel.stats();
    let mut waited = Duration::ZERO;
    let step = Duration::from_millis(10);
    let budget = Duration::from_secs(2);
    while stats.starts_ok.load(Ordering::Relaxed) == 0 && waited < budget {
        tokio::time::sleep(step).await;
        waited += step;
    }
    assert_eq!(
        stats.starts_ok.load(Ordering::Relaxed),
        1,
        "pal_tunnel should have started the single desired tunnel within {budget:?}"
    );
    assert_eq!(stats.starts_failed.load(Ordering::Relaxed), 0);

    trigger.fire();
    handle.await.expect("join").expect("clean shutdown");
}

/// Trivial helper used in assertions above so a future refactor
/// renaming the subsystems triggers a compile failure (the
/// `Subsystem::name` method's return value is exercised by every
/// `name_for_debug` call site).
trait NameForDebug {
    fn name_for_debug(&self) -> &'static str;
}

impl<T> NameForDebug for Arc<T>
where
    T: sng_core::Subsystem,
{
    fn name_for_debug(&self) -> &'static str {
        sng_core::Subsystem::name(self.as_ref())
    }
}
