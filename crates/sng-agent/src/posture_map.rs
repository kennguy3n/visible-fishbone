// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `PostureSnapshot` → `DevicePosture` mapping.
//!
//! The PAL collector ([`sng_pal::PostureSnapshot`]) and the ZTNA
//! evaluator ([`sng_ztna::DevicePosture`]) are deliberately
//! distinct types living in distinct crates: PAL uses rich,
//! four-state enums (`EdrState`, `AntivirusStatus`, …) that model
//! exactly what an OS probe can observe, while the broker uses
//! the flat booleans / `u32` ages its gates evaluate against. The
//! dependency only runs one way — PAL never depends on the broker
//! — so the projection between them lives here, in the agent, the
//! one crate that links both. (`sng_pal::CertificateHealth`'s doc
//! names this seam explicitly: "the agent maps this snapshot onto
//! the broker's `DevicePosture`".)
//!
//! # Fail-closed
//!
//! Every signal the snapshot can determine is projected on the
//! *deny* side of ambiguity: an enum that is anything other than
//! its explicit healthy variant (`Unknown`, `Disabled`,
//! `Unhealthy`, `NotInstalled`, …) maps to `false`, and a missing
//! age (`None`) maps to [`u32::MAX`]. A snapshot from an older
//! agent that predates the expanded signals deserialises those
//! fields to `Unknown` / `None` (see `PostureSnapshot`'s serde
//! defaults), so it too projects to a maximally-pessimistic
//! `DevicePosture` — a missing signal can never satisfy a gate.
//!
//! # The `base` parameter
//!
//! Two score signals have no authoritative counterpart in the
//! snapshot, so the mapping is an **overlay**: it takes the
//! device's current [`DevicePosture`] (e.g. the control-plane
//! device record, or [`DevicePosture::unmanaged`] for a device
//! with no prior record — itself fail-closed) and overrides only
//! the fields the snapshot can authoritatively observe, leaving
//! the rest to the base.
//!
//! * [`DevicePosture::os_patched`] means "the OS patch level meets
//!   the *tenant* minimum", a policy-relative judgement the agent
//!   cannot make at collection time (it has no
//!   [`sng_ztna::PostureRequirement`]). It is taken wholly from the
//!   base. The patch *recency* the snapshot does carry is projected
//!   independently onto [`DevicePosture::os_patch_days_since`],
//!   which the broker gates via `PostureRequirement::min_patch_days`.
//! * [`DevicePosture::screen_lock_configured`] means "a screen-lock
//!   *policy* is configured to engage within the idle window". PAL
//!   exposes only the live lock *state* (`Locked` / `Unlocked`),
//!   never the policy — and a device reporting posture is normally
//!   in use (unlocked), so deriving the signal from the live state
//!   would wrongly deny almost every active device. The
//!   configuration is therefore inherited from the base; a
//!   currently-`Locked` session is irrefutable proof a lock exists
//!   and engages, so it can only ever *confirm* the signal (set it
//!   `true`), never clear it.

use sng_pal::posture::{
    AntivirusStatus, CertificateHealth as PalCertificateHealth, DiskEncryptionState, EdrState,
    FirewallState, PostureSnapshot, ScreenLockState,
};
use sng_ztna::{CertificateHealth as ZtnaCertificateHealth, DevicePosture};

/// Project the PAL [`CertificateHealth`](PalCertificateHealth)
/// onto the broker's [`CertificateHealth`](ZtnaCertificateHealth).
///
/// The two enums are intentional mirrors (same variants, same
/// `snake_case` wire form); this is the one place the agent
/// depends on that being true, so a divergence surfaces here as a
/// compile error rather than as a silent wire mismatch.
const fn map_certificate_health(health: PalCertificateHealth) -> ZtnaCertificateHealth {
    match health {
        PalCertificateHealth::Healthy => ZtnaCertificateHealth::Healthy,
        PalCertificateHealth::Expiring => ZtnaCertificateHealth::Expiring,
        PalCertificateHealth::Expired => ZtnaCertificateHealth::Expired,
        PalCertificateHealth::Unknown => ZtnaCertificateHealth::Unknown,
    }
}

/// Overlay the signals a [`PostureSnapshot`] observes onto a
/// `base` [`DevicePosture`], returning the merged posture the
/// broker evaluates.
///
/// `base` supplies the fields the snapshot cannot determine
/// ([`DevicePosture::os_patched`] and
/// [`DevicePosture::screen_lock_configured`]); pass
/// [`DevicePosture::unmanaged`] when there is no prior record. The
/// device's freshness ([`DevicePosture::attested_at_ms`]) is taken
/// from the snapshot's `collected_at` so a re-collected snapshot
/// refreshes the attestation clock.
///
/// See the [module docs](self) for the fail-closed contract.
#[must_use]
pub fn merge_posture_snapshot(base: DevicePosture, snapshot: &PostureSnapshot) -> DevicePosture {
    // `collected_at` is the authoritative attestation time. A
    // pre-epoch timestamp is nonsensical; clamp it to 0 (treated
    // as "never attested" by the freshness gate) rather than
    // wrapping into a huge u64 that would read as fresh.
    let attested_at_ms = u64::try_from(snapshot.collected_at.timestamp_millis()).unwrap_or(0);

    // `screen_lock_configured` is a policy property the snapshot
    // cannot observe (PAL only sees the live lock state). Inherit it
    // from the base; a currently-locked session is proof a lock
    // exists, so it can only confirm — never clear — the signal,
    // avoiding a systematic false-deny of in-use (unlocked) devices.
    // See the module docs.
    let screen_lock_configured =
        base.screen_lock_configured || matches!(snapshot.screen_lock, ScreenLockState::Locked);

    base.with_disk_encrypted(matches!(
        snapshot.disk_encryption,
        DiskEncryptionState::Enabled
    ))
    .with_firewall_enabled(matches!(snapshot.firewall, FirewallState::Enabled))
    .with_screen_lock_configured(screen_lock_configured)
    .with_antimalware_running(matches!(snapshot.antivirus, AntivirusStatus::Enabled))
    .with_edr_healthy(matches!(snapshot.edr, EdrState::Healthy))
    .with_antivirus_enabled(matches!(snapshot.antivirus, AntivirusStatus::Enabled))
    .with_antivirus_definitions_age_hours(
        snapshot.antivirus_definitions_age_hours.unwrap_or(u32::MAX),
    )
    .with_os_patch_days_since(snapshot.os_patch_age_days.unwrap_or(u32::MAX))
    .with_os_patch_level(snapshot.os_patch_level.clone().unwrap_or_default())
    .with_certificate_health(map_certificate_health(snapshot.certificate_health))
    .with_attested_at_ms(attested_at_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    /// A snapshot with every observable signal healthy.
    fn healthy_snapshot() -> PostureSnapshot {
        let mut s = PostureSnapshot::unknown_at(Utc.timestamp_opt(1_700_000, 0).unwrap());
        s.disk_encryption = DiskEncryptionState::Enabled;
        s.firewall = FirewallState::Enabled;
        s.screen_lock = ScreenLockState::Locked;
        s.edr = EdrState::Healthy;
        s.antivirus = AntivirusStatus::Enabled;
        s.antivirus_definitions_age_hours = Some(2);
        s.os_patch_level = Some("10.0.22631.4317".to_owned());
        s.os_patch_age_days = Some(3);
        s.certificate_health = PalCertificateHealth::Healthy;
        s
    }

    #[test]
    fn healthy_snapshot_projects_all_signals_on() {
        // os_patched comes from base; screen_lock_configured is the
        // base value OR a confirming `Locked` state (here the
        // snapshot is locked, so it confirms `true` even though the
        // unmanaged base is `false`); everything else is observed.
        let base = DevicePosture::unmanaged().with_os_patched(true);
        let p = merge_posture_snapshot(base, &healthy_snapshot());

        assert!(p.disk_encrypted);
        assert!(p.firewall_enabled);
        assert!(
            p.screen_lock_configured,
            "a locked session confirms the lock even from an unmanaged base"
        );
        assert!(p.antimalware_running);
        assert!(p.edr_healthy);
        assert!(p.antivirus_enabled);
        assert_eq!(p.antivirus_definitions_age_hours, 2);
        assert_eq!(p.os_patch_days_since, 3);
        assert_eq!(p.os_patch_level, "10.0.22631.4317");
        assert_eq!(p.certificate_health, ZtnaCertificateHealth::Healthy);
        assert!(p.os_patched, "os_patched is preserved from the base");
        assert_eq!(p.attested_at_ms, 1_700_000_000);
    }

    #[test]
    fn unknown_snapshot_projects_fail_closed() {
        // The all-`Unknown` / `None` snapshot (also what an older
        // agent's payload deserialises to) must deny every gate.
        let snap = PostureSnapshot::unknown_at(Utc.timestamp_opt(42, 0).unwrap());
        // Start from a *pristine* base to prove the overlay forces
        // the observable signals back to the deny side rather than
        // leaving the base's optimistic values in place.
        let p = merge_posture_snapshot(DevicePosture::pristine(9_999), &snap);

        assert!(!p.disk_encrypted);
        assert!(!p.firewall_enabled);
        assert!(!p.antimalware_running);
        assert!(!p.edr_healthy);
        assert!(!p.antivirus_enabled);
        assert_eq!(p.antivirus_definitions_age_hours, u32::MAX);
        assert_eq!(p.os_patch_days_since, u32::MAX);
        assert_eq!(p.os_patch_level, "");
        assert_eq!(p.certificate_health, ZtnaCertificateHealth::Unknown);
        // os_patched and screen_lock_configured are not observable
        // from the snapshot (an `Unknown` lock state cannot confirm a
        // lock), so the base's values survive the overlay.
        assert!(p.os_patched);
        assert!(p.screen_lock_configured);
        assert_eq!(p.attested_at_ms, 42_000);
    }

    #[test]
    fn degraded_enums_are_not_treated_as_healthy() {
        // Anything other than the explicit healthy variant denies:
        // a suspended disk, an unhealthy (killed) EDR sensor, and
        // AV present-but-real-time-protection-off.
        let mut snap = healthy_snapshot();
        snap.disk_encryption = DiskEncryptionState::Suspended;
        snap.edr = EdrState::Unhealthy;
        snap.antivirus = AntivirusStatus::Disabled;
        snap.screen_lock = ScreenLockState::Unlocked;

        let p = merge_posture_snapshot(DevicePosture::unmanaged(), &snap);

        assert!(!p.disk_encrypted, "suspended encryption is not enabled");
        assert!(!p.edr_healthy, "an unhealthy sensor is not healthy");
        assert!(
            !p.antimalware_running && !p.antivirus_enabled,
            "AV with real-time protection off is not running"
        );
        assert!(
            !p.screen_lock_configured,
            "an unlocked session carries no positive proof, so the \
             fail-closed unmanaged base (false) survives"
        );
    }

    #[test]
    fn screen_lock_configuration_is_inherited_not_derived_from_live_state() {
        // Regression: a configuration property the snapshot cannot
        // observe must not be cleared by the transient lock state.
        // A device with a configured lock policy that is simply in
        // use (unlocked) must keep `screen_lock_configured` — the
        // earlier `Locked`-as-proxy mapping wrongly denied it.
        let configured_base = DevicePosture::unmanaged().with_screen_lock_configured(true);

        let mut in_use = healthy_snapshot();
        in_use.screen_lock = ScreenLockState::Unlocked;
        assert!(
            merge_posture_snapshot(configured_base.clone(), &in_use).screen_lock_configured,
            "an unlocked (in-use) device keeps its configured-lock base value"
        );

        let mut unobservable = healthy_snapshot();
        unobservable.screen_lock = ScreenLockState::Unknown;
        assert!(
            merge_posture_snapshot(configured_base, &unobservable).screen_lock_configured,
            "an unobservable lock state keeps the configured base value"
        );

        // And a `Locked` session positively confirms even when the
        // base did not assert it (e.g. a freshly enrolled device).
        let mut locked = healthy_snapshot();
        locked.screen_lock = ScreenLockState::Locked;
        assert!(
            merge_posture_snapshot(DevicePosture::unmanaged(), &locked).screen_lock_configured,
            "a locked session confirms a lock exists"
        );
    }

    #[test]
    fn certificate_health_round_trips_every_variant() {
        for (pal, want) in [
            (
                PalCertificateHealth::Healthy,
                ZtnaCertificateHealth::Healthy,
            ),
            (
                PalCertificateHealth::Expiring,
                ZtnaCertificateHealth::Expiring,
            ),
            (
                PalCertificateHealth::Expired,
                ZtnaCertificateHealth::Expired,
            ),
            (
                PalCertificateHealth::Unknown,
                ZtnaCertificateHealth::Unknown,
            ),
        ] {
            let mut snap = healthy_snapshot();
            snap.certificate_health = pal;
            let p = merge_posture_snapshot(DevicePosture::unmanaged(), &snap);
            assert_eq!(p.certificate_health, want);
        }
    }

    #[test]
    fn pre_epoch_collected_at_clamps_to_zero() {
        let mut snap = healthy_snapshot();
        snap.collected_at = Utc.timestamp_opt(-5, 0).unwrap();
        let p = merge_posture_snapshot(DevicePosture::unmanaged(), &snap);
        assert_eq!(
            p.attested_at_ms, 0,
            "a pre-epoch stamp reads as never-attested"
        );
    }
}
