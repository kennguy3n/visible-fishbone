//! Pure parsing / classification helpers shared by the OS
//! posture backends.
//!
//! Everything here is platform-independent and free of I/O, so
//! it compiles and is unit-tested on every target — including
//! CI's headless Linux — even for the Windows / macOS signals
//! whose *probe* (the command that produces the text these
//! functions parse) only runs on its native OS. The per-OS
//! modules are then thin shells: run the OS command, hand its
//! output to a function here, get a typed posture value back.

use chrono::{DateTime, Utc};
// `NaiveDate` / `TimeZone` are only referenced by the Windows
// hotfix-date parser (and the unit tests), so the import is gated
// to those builds to stay warning-clean on the Linux/macOS lib
// builds.
#[cfg(any(target_os = "windows", test))]
use chrono::{NaiveDate, TimeZone};

use super::{CertificateHealth, EdrState};
// `AntivirusStatus` is only referenced by the Windows Security
// Center decoders (and the unit tests).
#[cfg(any(target_os = "windows", test))]
use super::AntivirusStatus;

/// Whole hours elapsed from `earlier` to `now`, saturating at 0
/// for a non-positive delta (clock skew / a timestamp in the
/// future). Returns `u32::MAX` rather than overflowing for an
/// absurdly old timestamp.
// Used by the Linux (ClamAV signature mtime) and macOS (XProtect
// bundle mtime) AV-freshness probes; the Windows backend derives
// freshness from a Security Center flag instead, so the helper is
// gated to the builds that call it.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
#[must_use]
pub(crate) fn hours_since(earlier: DateTime<Utc>, now: DateTime<Utc>) -> u32 {
    let secs = now.signed_duration_since(earlier).num_seconds();
    if secs <= 0 {
        return 0;
    }
    u32::try_from(secs / 3_600).unwrap_or(u32::MAX)
}

/// Whole days elapsed from `earlier` to `now`, saturating like
/// [`hours_since`].
#[must_use]
pub(crate) fn days_since(earlier: DateTime<Utc>, now: DateTime<Utc>) -> u32 {
    let secs = now.signed_duration_since(earlier).num_seconds();
    if secs <= 0 {
        return 0;
    }
    u32::try_from(secs / 86_400).unwrap_or(u32::MAX)
}

/// Classify identity-certificate health from its validity
/// window. `renew_within_days` is the lead time before
/// `not_after` at which the leaf is flagged
/// [`CertificateHealth::Expiring`] so the fleet can be
/// re-enrolled before access actually breaks.
#[must_use]
pub(crate) fn certificate_health(
    not_before: Option<DateTime<Utc>>,
    not_after: DateTime<Utc>,
    now: DateTime<Utc>,
    renew_within_days: i64,
) -> CertificateHealth {
    if now >= not_after {
        return CertificateHealth::Expired;
    }
    if let Some(nb) = not_before
        && now < nb
    {
        // Not yet valid — treat as expired (unusable now).
        return CertificateHealth::Expired;
    }
    let renew_at = not_after - chrono::Duration::days(renew_within_days.max(0));
    if now >= renew_at {
        CertificateHealth::Expiring
    } else {
        CertificateHealth::Healthy
    }
}

/// Lower-cased process / extension / bundle-id fragments that
/// uniquely identify a known EDR sensor across vendors.
///
/// Matching is substring-based so a versioned or path-qualified
/// name (`falcon-sensor`, `com.crowdstrike.falcon.Agent`) is
/// still recognised regardless of the exact prefix/suffix.
/// Because a *false positive* marks a device as EDR-healthy when
/// it is not — a fail-**open** error, the opposite of this
/// crate's fail-closed contract, and enough to slip a device
/// past a `require_edr` gate — every entry is a vendor-unique
/// token rather than a bare product word. Generic words that
/// collide with common non-EDR software (`sentinel` → Redis
/// Sentinel, `cortex` → Grafana Cortex, `carbon` → Graphite
/// carbon, `traps` → `bootstrapped`) are deliberately avoided in
/// favour of the specific binary / bundle names below; an
/// unrecognised sensor degrades to `NotInstalled` (deny), which
/// is the safe direction.
pub(crate) const KNOWN_EDR_MARKERS: &[&str] = &[
    // CrowdStrike Falcon
    "falcon-sensor", // Linux daemon
    "csfalcon",      // Windows CSFalconService / CSFalconContainer
    "crowdstrike",   // macOS bundle com.crowdstrike.falcon.*
    // SentinelOne
    "sentinelone",   // macOS bundle com.sentinelone.*
    "sentineld",     // Linux daemon
    "sentinelagent", // SentinelAgent process
    "s1-agent",      // Linux package alias
    // VMware Carbon Black
    "cbagent",     // cbagentd
    "carbonblack", // macOS bundle com.vmware.carbonblack.*
    // BlackBerry Cylance
    "cylance", // CylanceSvc / cylanced
    // Microsoft Defender for Endpoint
    "wdavdaemon", // macOS/Linux daemon
    "mdatp",      // Defender ATP daemon / CLI
    // Palo Alto Cortex XDR / Traps
    "cortex-xdr",       // Cortex XDR agent (dashed spelling)
    "cortexxdr",        // Cortex XDR agent (concatenated spelling)
    "paloaltonetworks", // macOS bundle com.paloaltonetworks.*
    "traps_pmd",        // Traps (legacy) process-manager daemon
    // Sophos Intercept X
    "sophos", // savd / com.sophos.*
    // Elastic Defend
    "elastic-endpoint",
];

/// Decide EDR health from the set of currently-running process
/// names (already lower-cased) against [`KNOWN_EDR_MARKERS`].
///
/// On Linux there is no Security-Center-style health bit, so a
/// recognised sensor *process* being present is treated as
/// [`EdrState::Healthy`]; its absence is [`EdrState::NotInstalled`].
/// A caller that cannot enumerate processes at all passes
/// `could_enumerate = false` to get [`EdrState::Unknown`] instead
/// of a false `NotInstalled`.
#[cfg(any(target_os = "linux", test))]
#[must_use]
pub(crate) fn edr_state_from_processes<S: AsRef<str>>(
    running_process_names: &[S],
    could_enumerate: bool,
) -> EdrState {
    if !could_enumerate {
        return EdrState::Unknown;
    }
    let found = running_process_names.iter().any(|name| {
        let lname = name.as_ref().to_ascii_lowercase();
        KNOWN_EDR_MARKERS
            .iter()
            .any(|marker| !marker.is_empty() && lname.contains(marker))
    });
    if found {
        EdrState::Healthy
    } else {
        EdrState::NotInstalled
    }
}

/// Decode a Windows Security Center `productState` DWORD into an
/// antivirus status plus a "definitions up to date" flag.
///
/// `productState` is an undocumented-but-stable bitfield exposed
/// by the `root\SecurityCenter2` WMI `AntiVirusProduct` /
/// `AntiSpywareProduct` classes. The three bytes that matter:
///
/// * bit `0x1000` of the middle byte — real-time protection
///   **on**.
/// * bit `0x0010` of the low byte — signature definitions
///   **out of date**.
///
/// This is the same decode every MDM / PowerShell WSC script
/// uses (`Get-CimInstance -Namespace root/SecurityCenter2
/// -ClassName AntiVirusProduct`).
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn classify_security_center_av(product_state: u32) -> (AntivirusStatus, bool) {
    let realtime_on = product_state & 0x1000 != 0;
    let out_of_date = product_state & 0x0010 != 0;
    let status = if realtime_on {
        AntivirusStatus::Enabled
    } else {
        AntivirusStatus::Disabled
    };
    (status, !out_of_date)
}

/// Map an EDR product reported by Security Center to an
/// [`EdrState`], given whether real-time protection is on. An
/// EDR product that registers with WSC but reports itself off
/// is [`EdrState::Unhealthy`] rather than `NotInstalled`.
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn edr_state_from_security_center(
    found_edr_product: bool,
    realtime_on: bool,
) -> EdrState {
    match (found_edr_product, realtime_on) {
        (true, true) => EdrState::Healthy,
        (true, false) => EdrState::Unhealthy,
        (false, _) => EdrState::NotInstalled,
    }
}

/// Parse one line of `Get-CimInstance … AntiVirusProduct`
/// output formatted by the probe as `displayName|productState`
/// (productState in decimal). Returns `(display_name,
/// product_state)`.
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn parse_av_product_line(line: &str) -> Option<(String, u32)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let (name, state) = line.rsplit_once('|')?;
    let state: u32 = state.trim().parse().ok()?;
    Some((name.trim().to_owned(), state))
}

/// Pick the most relevant AV product from a `displayName|state`
/// listing: prefer an enabled product, else the first one. Also
/// reports whether any listed product's display name looks like
/// an EDR/XDR sensor (used for the Windows EDR signal, which
/// rides the same WSC listing).
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn select_av_product(stdout: &str) -> Option<SecurityCenterAv> {
    let mut chosen: Option<(String, u32)> = None;
    let mut found_edr = false;
    let mut edr_realtime_on = false;
    for line in stdout.lines() {
        let Some((name, state)) = parse_av_product_line(line) else {
            continue;
        };
        let (status, _up_to_date) = classify_security_center_av(state);
        let lname = name.to_ascii_lowercase();
        let looks_edr = KNOWN_EDR_MARKERS
            .iter()
            .any(|m| !m.is_empty() && lname.contains(m))
            || lname.contains("defender for endpoint")
            || lname.contains("xdr")
            || lname.contains("edr");
        if looks_edr {
            found_edr = true;
            if matches!(status, AntivirusStatus::Enabled) {
                edr_realtime_on = true;
            }
        }
        let take = match &chosen {
            None => true,
            Some((_, prev_state)) => {
                // Prefer an enabled product over a disabled one.
                let prev_enabled = matches!(
                    classify_security_center_av(*prev_state).0,
                    AntivirusStatus::Enabled
                );
                let this_enabled = matches!(status, AntivirusStatus::Enabled);
                this_enabled && !prev_enabled
            }
        };
        if take {
            chosen = Some((name, state));
        }
    }
    chosen.map(|(name, state)| {
        let (status, up_to_date) = classify_security_center_av(state);
        SecurityCenterAv {
            display_name: name,
            status,
            definitions_up_to_date: up_to_date,
            found_edr_product: found_edr,
            edr_realtime_on,
        }
    })
}

/// Outcome of decoding a Security Center AV listing.
#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SecurityCenterAv {
    /// Display name of the chosen AV product.
    pub(crate) display_name: String,
    /// Real-time-protection status of the chosen product.
    pub(crate) status: AntivirusStatus,
    /// Whether the chosen product's signature definitions are
    /// current.
    pub(crate) definitions_up_to_date: bool,
    /// Whether any listed product looks like an EDR/XDR sensor.
    pub(crate) found_edr_product: bool,
    /// Whether an EDR product (if any) has real-time on.
    pub(crate) edr_realtime_on: bool,
}

/// Parse an ISO-8601 `yyyy-MM-dd` date (the format the Windows
/// hotfix probe is asked to emit) into a UTC midnight instant.
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn parse_iso_date(s: &str) -> Option<DateTime<Utc>> {
    let date = NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok()?;
    let dt = date.and_hms_opt(0, 0, 0)?;
    Some(Utc.from_utc_datetime(&dt))
}

/// Parse the newest hotfix install date from the Windows probe.
/// The probe emits one ISO date (`yyyy-MM-dd`) per installed
/// hotfix that carries an `InstalledOn` value; we take the
/// maximum. Empty / unparseable input yields `None`.
#[cfg(any(target_os = "windows", test))]
#[must_use]
pub(crate) fn newest_hotfix_date(stdout: &str) -> Option<DateTime<Utc>> {
    stdout.lines().filter_map(parse_iso_date).max()
}

/// Parse a macOS `defaults read … LastFullSuccessfulDate`
/// value, e.g. `2026-04-10 12:34:56 +0000`, into a UTC instant.
#[cfg(any(target_os = "macos", test))]
#[must_use]
pub(crate) fn parse_macos_defaults_date(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    // `%z` accepts `+0000`; macOS prints a space before it.
    DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S %z")
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Decide EDR health from `systemextensionsctl list` output.
///
/// macOS Endpoint Security agents (CrowdStrike, SentinelOne,
/// Defender, etc.) register a system extension that
/// `systemextensionsctl list` prints with a state field like
/// `[activated enabled]`. A recognised EDR extension that is
/// `activated enabled` is [`EdrState::Healthy`]; one that is
/// present in some other state is [`EdrState::Unhealthy`]; none
/// found is [`EdrState::NotInstalled`].
#[cfg(any(target_os = "macos", test))]
#[must_use]
pub(crate) fn edr_state_from_systemextensions(stdout: &str) -> EdrState {
    let mut found = false;
    for line in stdout.lines() {
        let lline = line.to_ascii_lowercase();
        let looks_edr = KNOWN_EDR_MARKERS
            .iter()
            .any(|m| !m.is_empty() && lline.contains(m));
        if !looks_edr {
            continue;
        }
        found = true;
        if lline.contains("[activated enabled]") {
            return EdrState::Healthy;
        }
    }
    if found {
        EdrState::Unhealthy
    } else {
        EdrState::NotInstalled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn ts(y: i32, mo: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn hours_and_days_saturate_on_skew() {
        let now = ts(2026, 6, 1);
        assert_eq!(hours_since(now, now), 0);
        // earlier in the future -> 0
        assert_eq!(hours_since(ts(2026, 6, 2), now), 0);
        assert_eq!(days_since(ts(2026, 5, 1), now), 31);
        assert_eq!(hours_since(ts(2026, 5, 31), now), 24);
    }

    #[test]
    fn certificate_health_windows() {
        let now = ts(2026, 6, 1);
        // Expired.
        assert_eq!(
            certificate_health(None, ts(2026, 5, 1), now, 14),
            CertificateHealth::Expired
        );
        // Not yet valid -> expired (unusable).
        assert_eq!(
            certificate_health(Some(ts(2026, 7, 1)), ts(2027, 1, 1), now, 14),
            CertificateHealth::Expired
        );
        // Expiring inside the 14-day renewal window.
        assert_eq!(
            certificate_health(None, ts(2026, 6, 10), now, 14),
            CertificateHealth::Expiring
        );
        // Healthy, far from expiry.
        assert_eq!(
            certificate_health(Some(ts(2026, 1, 1)), ts(2027, 1, 1), now, 14),
            CertificateHealth::Healthy
        );
    }

    #[test]
    fn edr_from_processes() {
        assert_eq!(
            edr_state_from_processes(&["bash", "falcon-sensor", "sshd"], true),
            EdrState::Healthy
        );
        assert_eq!(
            edr_state_from_processes(&["CSFalconService"], true),
            EdrState::Healthy
        );
        assert_eq!(
            edr_state_from_processes(&["bash", "sshd"], true),
            EdrState::NotInstalled
        );
        // Fail-open guard: generic words that collide with common
        // non-EDR software must NOT be mistaken for a sensor, or a
        // device with no EDR would slip past a `require_edr` gate.
        // Redis Sentinel, Grafana Cortex, Graphite carbon-cache, and
        // a process that merely contains "traps".
        assert_eq!(
            edr_state_from_processes(
                &["redis-sentinel", "cortex", "carbon-cache", "bootstrapped"],
                true
            ),
            EdrState::NotInstalled
        );
        // Cannot enumerate -> Unknown, never a false NotInstalled.
        assert_eq!(
            edr_state_from_processes::<&str>(&[], false),
            EdrState::Unknown
        );
    }

    #[test]
    fn security_center_av_decode() {
        // 0x61100: realtime on (0x1000) + up to date (0x0010 clear).
        let (status, up_to_date) = classify_security_center_av(0x0006_1100);
        assert_eq!(status, AntivirusStatus::Enabled);
        assert!(up_to_date);
        // realtime on but out of date (0x0010 set).
        let (status, up_to_date) = classify_security_center_av(0x0006_1110);
        assert_eq!(status, AntivirusStatus::Enabled);
        assert!(!up_to_date);
        // realtime off.
        let (status, _) = classify_security_center_av(0x0006_0100);
        assert_eq!(status, AntivirusStatus::Disabled);
    }

    #[test]
    fn edr_security_center_mapping() {
        assert_eq!(
            edr_state_from_security_center(true, true),
            EdrState::Healthy
        );
        assert_eq!(
            edr_state_from_security_center(true, false),
            EdrState::Unhealthy
        );
        assert_eq!(
            edr_state_from_security_center(false, true),
            EdrState::NotInstalled
        );
    }

    #[test]
    fn select_av_prefers_enabled_and_flags_edr() {
        let stdout = "Windows Defender|266240\n\
                      CrowdStrike Falcon Sensor|397568\n";
        // 266240 = 0x41000 (realtime on). 397568 = 0x61100.
        let av = select_av_product(stdout).expect("an av");
        assert_eq!(av.status, AntivirusStatus::Enabled);
        assert!(av.found_edr_product);
        assert!(av.edr_realtime_on);
    }

    #[test]
    fn select_av_none_on_empty() {
        assert_eq!(select_av_product("\n   \n"), None);
        assert_eq!(parse_av_product_line("garbage-no-pipe"), None);
    }

    #[test]
    fn hotfix_date_parsing() {
        let stdout = "2026-01-02\n2026-05-30\nnot-a-date\n2026-03-15\n";
        assert_eq!(newest_hotfix_date(stdout), Some(ts(2026, 5, 30)));
        assert_eq!(newest_hotfix_date("\n\n"), None);
    }

    #[test]
    fn macos_defaults_date_parsing() {
        let dt = parse_macos_defaults_date("2026-04-10 12:34:56 +0000").expect("date");
        assert_eq!(dt, Utc.with_ymd_and_hms(2026, 4, 10, 12, 34, 56).unwrap());
        assert_eq!(parse_macos_defaults_date("garbage"), None);
    }

    #[test]
    fn systemextensions_edr_states() {
        let healthy = "enabled\tactive\tteamID\tcom.crowdstrike.falcon.Agent (1.0/1)\tFalcon\t[activated enabled]";
        assert_eq!(edr_state_from_systemextensions(healthy), EdrState::Healthy);
        let unhealthy = "enabled\tactive\tteamID\tcom.sentinelone.agent (1.0/1)\tS1\t[activated waiting for user]";
        assert_eq!(
            edr_state_from_systemextensions(unhealthy),
            EdrState::Unhealthy
        );
        let none = "enabled\tactive\tteamID\tcom.example.vpn (1.0/1)\tVPN\t[activated enabled]";
        assert_eq!(
            edr_state_from_systemextensions(none),
            EdrState::NotInstalled
        );
    }
}
