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

//! End-to-end integration tests for the `sng-edge` supervisor.
//!
//! These cover the seams the per-subsystem unit tests cannot:
//! the [`build_edge`] composition pass + backend rejection. We
//! deliberately don't drive `supervisor.run()` end-to-end
//! (that requires a live control-plane mock); composition + the
//! ten registered subsystem handles are enough to pin down the
//! binary crate's wiring contract without duplicating the
//! per-crate unit tests already living in each library crate.

use clap::Parser;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use sng_core::ids::{DeviceId, SiteId, TenantId};
use sng_edge::config::{
    CommsConfig, DnsConfig, EdgeConfig, FwConfig, HaConfig, IdentityConfig, IpsConfig,
    PolicyConfig, SdwanConfig, SupervisorConfig, SwgConfig, TelemetryConfig, UpdaterConfig,
    ZtnaConfig,
};
use sng_edge::{Cli, EdgeBuildError, PalBackend, UpdaterBackend, build_edge};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

/// Mint a self-signed Ed25519 cert + matching key in PEM form.
/// rcgen is already pulled in via sister-crate test suites; we
/// depend on it here as a dev-dependency for the same purpose.
fn mint_identity_pem() -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
    let mut params =
        CertificateParams::new(vec!["edge-integration-test".into()]).expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "edge-integration-test");
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

/// Build a syntactically valid edge config rooted at a real
/// on-disk PEM pair. The returned `_dir` is the `TempDir`
/// holding the PEM files; it must outlive the returned
/// `EdgeConfig`.
fn fresh_config() -> (EdgeConfig, TempDir) {
    let (cert_path, key_path, dir) = write_identity_to_disk();
    let cfg = EdgeConfig {
        identity: IdentityConfig {
            tenant_id: TenantId::from_uuid(Uuid::from_u128(0xA11C_E001)),
            device_id: DeviceId::from_uuid(Uuid::from_u128(0xDEAD_BEEF)),
            site_id: SiteId::from_uuid(Uuid::from_u128(0x517E_0001)),
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
        dns: DnsConfig::default(),
        fw: FwConfig::default(),
        ips: IpsConfig::default(),
        swg: SwgConfig::default(),
        ztna: ZtnaConfig::default(),
        sdwan: SdwanConfig::default(),
        ha: HaConfig::default(),
        updater: UpdaterConfig::default(),
        supervisor: SupervisorConfig::default(),
    };
    (cfg, dir)
}

fn fresh_cli() -> Cli {
    // Use the binary's actual clap parser so the `default_value_t`
    // attributes are honoured exactly as they would be at
    // runtime. `--config` is required by the schema so we
    // hand it a non-existent placeholder; `build_edge` itself
    // never reads it (the caller already loaded the config).
    Cli::try_parse_from(["sng-edge", "--config", "/dev/null"]).expect("parse")
}

#[tokio::test(flavor = "multi_thread")]
async fn build_edge_assembles_eleven_subsystems_with_in_memory_backends() {
    let cli = fresh_cli();
    let (cfg, _dir) = fresh_config();
    let built = build_edge(&cli, &cfg).expect("build_edge");

    // Strong handles for every adapter so a future refactor
    // that drops one would force a compile / test failure
    // here rather than silently regressing the wiring.
    assert_eq!(built.telemetry.name_for_debug(), "telemetry");
    assert_eq!(built.comms.name_for_debug(), "comms");
    assert_eq!(built.policy_eval.name_for_debug(), "policy_eval");
    assert_eq!(built.dns.name_for_debug(), "dns");
    assert_eq!(built.fw.name_for_debug(), "fw");
    assert_eq!(built.ips.name_for_debug(), "ips");
    assert_eq!(built.swg.name_for_debug(), "swg");
    assert_eq!(built.ztna.name_for_debug(), "ztna");
    assert_eq!(built.sdwan.name_for_debug(), "sdwan");
    assert_eq!(built.ha.name_for_debug(), "ha");
    assert_eq!(built.updater.name_for_debug(), "updater");
}

#[tokio::test(flavor = "multi_thread")]
async fn build_edge_rejects_native_pal_backend_up_front() {
    let cli = Cli::try_parse_from([
        "sng-edge",
        "--config",
        "/dev/null",
        "--pal-backend",
        "native",
    ])
    .expect("parse");
    let (cfg, _dir) = fresh_config();
    let err = build_edge(&cli, &cfg).unwrap_err();
    match err {
        EdgeBuildError::UnsupportedPalBackend(backend) => {
            assert_eq!(backend, PalBackend::Native);
        }
        other => panic!("expected UnsupportedPalBackend, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn build_edge_rejects_disk_updater_backend_up_front() {
    let cli = Cli::try_parse_from([
        "sng-edge",
        "--config",
        "/dev/null",
        "--updater-backend",
        "disk",
    ])
    .expect("parse");
    let (cfg, _dir) = fresh_config();
    let err = build_edge(&cli, &cfg).unwrap_err();
    match err {
        EdgeBuildError::UnsupportedUpdaterBackend(backend) => {
            assert_eq!(backend, UpdaterBackend::Disk);
        }
        other => panic!("expected UnsupportedUpdaterBackend, got {other:?}"),
    }
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
