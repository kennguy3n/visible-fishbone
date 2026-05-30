//! `suricata.yaml` config generation.
//!
//! Translates the IPS-relevant slice of a compiled policy bundle
//! into a `suricata.yaml` document the production binary consumes
//! on `-c`. The output is intentionally deterministic — two
//! identical [`IpsConfigInput`]s produce byte-identical YAML, so
//! the manager can SHA-256 the rendered text and skip a kernel
//! restart when nothing has changed.
//!
//! The writer is hand-rolled (no third-party YAML serializer).
//! The Suricata config surface we actually populate is small
//! (capture, defrag, app-layer, detect, outputs, vars) and fully
//! controlled by us, so a writer avoids pulling in a 300 kLoC
//! parser as a hard dependency just to emit a few hundred bytes.
//! The emitter validates every string against the YAML escaping
//! rules and refuses to emit anything that would require quoting
//! semantics it does not implement.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::IpsError;

/// Operating mode for the Suricata data plane.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpsRuntime {
    /// Inline mode: Suricata sits in the packet path and can
    /// drop. This is the production deployment for the edge VM.
    Inline,
    /// IDS mode: packets are copied; detect-only. Useful for the
    /// initial roll-out window where the operator wants
    /// observability before enabling drop.
    Ids,
}

impl IpsRuntime {
    const fn af_packet_copy_mode(self) -> &'static str {
        match self {
            Self::Inline => "ips",
            Self::Ids => "none",
        }
    }

    const fn detect_default_drop(self) -> bool {
        matches!(self, Self::Inline)
    }
}

/// Operator-facing knob bundle. Built from the policy bundle's
/// IPS section by [`crate::manager::IpsManager`] and fed into
/// [`ConfigGenerator::render`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpsConfigInput {
    /// Where the in-flight rule bundle is staged on disk.
    /// `suricata -T` validates the file at this path and the
    /// running binary re-reads it on `SIGHUP`.
    pub rule_file_path: PathBuf,
    /// `af-packet` interface (or `pcap` interface for IDS mode).
    /// Corresponds to the edge VM's data-path NIC.
    pub interface: String,
    /// IDS / IPS mode toggle.
    pub runtime: IpsRuntime,
    /// EVE JSON output path. The manager tails this file to
    /// normalise alerts into the workspace event schema.
    pub eve_log_path: PathBuf,
    /// Unix-socket path the stats reader polls.
    pub stats_socket_path: PathBuf,
    /// HOME_NET CIDRs — Suricata's "trusted" address set. Maps
    /// to the operator's `branch.lan` / `dc.dmz` networks from
    /// the policy bundle.
    pub home_net: Vec<String>,
    /// EXTERNAL_NET — usually `!$HOME_NET` but operators with
    /// site-to-site overlays sometimes want to flip this.
    pub external_net: Vec<String>,
    /// Application layer toggles keyed by parser name (`tls`,
    /// `http`, `dns`, `smb`). `true` enables the parser. Unknown
    /// names are passed through (Suricata silently ignores them)
    /// so the operator can experiment with new parsers without
    /// requiring a `sng-ips` release.
    pub app_layer_enabled: BTreeMap<String, bool>,
    /// Detect-engine drop policy override. `Some(true)` forces
    /// drop on alert regardless of [`Self::runtime`]; `None`
    /// inherits from runtime mode.
    pub force_drop_on_alert: Option<bool>,
    /// Maximum number of detection threads. `None` = auto.
    pub max_pending_packets: Option<u32>,
}

impl IpsConfigInput {
    /// Build a sane default config for the supplied runtime.
    /// Operators typically only override the interface, rule
    /// path, log paths, and HOME_NET — every other knob has a
    /// safe default.
    #[must_use]
    pub fn defaults(runtime: IpsRuntime) -> Self {
        let mut app_layer = BTreeMap::new();
        for parser in ["tls", "http", "dns", "smb", "ssh", "smtp", "ftp"] {
            app_layer.insert(parser.to_owned(), true);
        }
        Self {
            rule_file_path: PathBuf::from("/var/lib/suricata/rules/sng.rules"),
            interface: "eth0".to_owned(),
            runtime,
            eve_log_path: PathBuf::from("/var/log/suricata/eve.json"),
            stats_socket_path: PathBuf::from("/run/suricata/suricata-command.socket"),
            home_net: vec!["10.0.0.0/8".to_owned(), "192.168.0.0/16".to_owned()],
            external_net: vec!["!$HOME_NET".to_owned()],
            app_layer_enabled: app_layer,
            force_drop_on_alert: None,
            max_pending_packets: Some(1024),
        }
    }
}

/// Rendered config + the SHA-256 of the rendered text. The
/// manager hashes the rendered bytes to decide whether a
/// reload is actually needed: two identical inputs render to the
/// same byte string and therefore the same digest, so a config
/// rotation that does not change anything substantive does not
/// trigger a kernel restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuricataConfig {
    text: String,
    digest: [u8; 32],
}

impl SuricataConfig {
    /// Rendered YAML text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Rendered YAML as raw bytes (convenience for writers that
    /// take `&[u8]`).
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// SHA-256 of the rendered text. Stable across runs for the
    /// same input.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Hex-encoded digest — useful for log messages and
    /// telemetry attributes.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }
}

/// Stateless YAML renderer. The struct exists so the public API
/// is method-shaped and the type can grow cache / pool state in
/// the future without breaking call sites.
#[derive(Clone, Debug, Default)]
pub struct ConfigGenerator {
    _private: (),
}

impl ConfigGenerator {
    /// Construct a generator.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Render `input` to a [`SuricataConfig`].
    pub fn render(&self, input: &IpsConfigInput) -> Result<SuricataConfig, IpsError> {
        // Validate strings up-front so we never emit a half-written
        // document that would crash `suricata -T` with a confusing
        // error.
        validate_plain(&input.interface, "interface")?;
        validate_path(&input.rule_file_path, "rule_file_path")?;
        validate_path(&input.eve_log_path, "eve_log_path")?;
        validate_path(&input.stats_socket_path, "stats_socket_path")?;
        for net in &input.home_net {
            validate_plain(net, "home_net entry")?;
        }
        for net in &input.external_net {
            validate_plain(net, "external_net entry")?;
        }
        for parser in input.app_layer_enabled.keys() {
            validate_plain(parser, "app_layer parser name")?;
        }

        let mut out = String::with_capacity(2048);
        out.push_str("%YAML 1.1\n");
        out.push_str("---\n");
        // Header marker — useful for operators grepping a
        // running file to confirm SNG wrote it.
        out.push_str("# Generated by sng-ips ConfigGenerator. Do not edit by hand.\n");

        // Variables block. HOME_NET / EXTERNAL_NET are
        // referenced by every rule so they must be first.
        out.push_str("vars:\n");
        out.push_str("  address-groups:\n");
        // `write!` into the buffer rather than allocating an
        // intermediate `String` per line — clippy's
        // `format_push_string` lint catches the allocation, but
        // more importantly this keeps the YAML emitter
        // allocation-free per line on the hot path. The `_` bind
        // is needed because `Write` for `String` is infallible
        // but the trait method still returns `fmt::Result`.
        let _ = writeln!(out, "    HOME_NET: \"{}\"", join_quoted(&input.home_net));
        let _ = writeln!(
            out,
            "    EXTERNAL_NET: \"{}\"",
            join_quoted(&input.external_net)
        );

        // Default rule path so a SIGHUP-driven reload picks the
        // staged file up without restating it elsewhere.
        out.push_str("default-rule-path: \"");
        out.push_str(parent_or_root(&input.rule_file_path));
        out.push_str("\"\n");
        out.push_str("rule-files:\n");
        out.push_str("  - \"");
        out.push_str(file_name(&input.rule_file_path));
        out.push_str("\"\n");

        // Detection engine — most of the knobs are at default;
        // we only override what differs from upstream Suricata
        // defaults.
        out.push_str("detect:\n");
        let drop_on_alert = input
            .force_drop_on_alert
            .unwrap_or_else(|| input.runtime.detect_default_drop());
        let _ = writeln!(out, "  drop-on-alert: {drop_on_alert}");

        if let Some(max_pending) = input.max_pending_packets {
            let _ = writeln!(out, "max-pending-packets: {max_pending}");
        }

        // Capture: af-packet stanza. Suricata accepts a list so
        // operators can later bind multiple NICs.
        out.push_str("af-packet:\n");
        let _ = writeln!(out, "  - interface: \"{}\"", input.interface);
        let _ = writeln!(
            out,
            "    copy-mode: {}",
            input.runtime.af_packet_copy_mode()
        );
        out.push_str("    copy-iface: \"\"\n");
        out.push_str("    cluster-id: 99\n");
        out.push_str("    cluster-type: cluster_flow\n");
        out.push_str("    defrag: yes\n");
        out.push_str("    use-mmap: yes\n");
        out.push_str("    tpacket-v3: yes\n");

        // App layer parsers. BTreeMap iteration is sorted, so
        // the output is stable.
        out.push_str("app-layer:\n");
        out.push_str("  protocols:\n");
        for (parser, enabled) in &input.app_layer_enabled {
            let _ = writeln!(
                out,
                "    {parser}:\n      enabled: {}",
                if *enabled { "yes" } else { "no" }
            );
        }

        // Outputs: EVE JSON file the manager tails, plus a
        // stats unix socket the supervisor reads.
        out.push_str("outputs:\n");
        out.push_str("  - eve-log:\n");
        out.push_str("      enabled: yes\n");
        out.push_str("      filetype: regular\n");
        let _ = writeln!(out, "      filename: \"{}\"", input.eve_log_path.display());
        out.push_str("      types:\n");
        // Match the EVE record types our `eve.rs` parser knows
        // about. Anything else is decoded as `Unknown` but not
        // dropped, so adding a type here later is forward-safe.
        for ty in ["alert", "anomaly", "dns", "http", "tls", "flow", "fileinfo"] {
            let _ = writeln!(out, "        - {ty}");
        }
        out.push_str("  - stats:\n");
        out.push_str("      enabled: yes\n");
        out.push_str("      filetype: unix_stream\n");
        let _ = writeln!(
            out,
            "      filename: \"{}\"",
            input.stats_socket_path.display()
        );

        let bytes = out.as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest_bytes: [u8; 32] = hasher.finalize().into();
        Ok(SuricataConfig {
            text: out,
            digest: digest_bytes,
        })
    }
}

fn validate_plain(s: &str, field: &str) -> Result<(), IpsError> {
    if s.is_empty() {
        return Err(IpsError::Config(format!("{field} must not be empty")));
    }
    for c in s.chars() {
        if c == '"' || c == '\\' || c.is_control() {
            return Err(IpsError::Config(format!(
                "{field} {s:?} contains a character ({c:?}) the YAML writer cannot escape",
            )));
        }
    }
    Ok(())
}

fn validate_path(p: &std::path::Path, field: &str) -> Result<(), IpsError> {
    let s = p.to_string_lossy();
    validate_plain(&s, field)
}

fn parent_or_root(path: &std::path::Path) -> &str {
    path.parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
}

fn file_name(path: &std::path::Path) -> &str {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("")
}

fn join_quoted(parts: &[String]) -> String {
    // HOME_NET / EXTERNAL_NET are emitted as Suricata's
    // comma-separated bracketed list inside a YAML string. The
    // wrapping double-quotes are added by the caller.
    let inner = parts.join(",");
    format!("[{inner}]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn baseline() -> IpsConfigInput {
        IpsConfigInput::defaults(IpsRuntime::Inline)
    }

    #[test]
    fn render_inline_emits_ips_copy_mode_and_drop_on_alert() {
        let g = ConfigGenerator::new();
        let cfg = g.render(&baseline()).expect("render");
        let t = cfg.text();
        assert!(t.contains("copy-mode: ips"), "{t}");
        assert!(t.contains("drop-on-alert: true"), "{t}");
    }

    #[test]
    fn render_ids_mode_does_not_drop_by_default() {
        let g = ConfigGenerator::new();
        let cfg = g
            .render(&IpsConfigInput::defaults(IpsRuntime::Ids))
            .unwrap();
        let t = cfg.text();
        assert!(t.contains("copy-mode: none"), "{t}");
        assert!(t.contains("drop-on-alert: false"), "{t}");
    }

    #[test]
    fn render_force_drop_overrides_runtime() {
        let mut input = IpsConfigInput::defaults(IpsRuntime::Ids);
        input.force_drop_on_alert = Some(true);
        let cfg = ConfigGenerator::new().render(&input).unwrap();
        assert!(cfg.text().contains("drop-on-alert: true"));
    }

    #[test]
    fn render_emits_home_net_and_external_net() {
        let mut input = baseline();
        input.home_net = vec!["172.16.0.0/12".into(), "fd00::/8".into()];
        input.external_net = vec!["!$HOME_NET".into()];
        let cfg = ConfigGenerator::new().render(&input).unwrap();
        let t = cfg.text();
        assert!(t.contains(r#"HOME_NET: "[172.16.0.0/12,fd00::/8]""#), "{t}");
        assert!(t.contains(r#"EXTERNAL_NET: "[!$HOME_NET]""#), "{t}");
    }

    #[test]
    fn render_emits_rule_file_path_and_default_rule_path() {
        let mut input = baseline();
        input.rule_file_path = PathBuf::from("/opt/sng/ips/rules/staged.rules");
        let cfg = ConfigGenerator::new().render(&input).unwrap();
        let t = cfg.text();
        assert!(
            t.contains(r#"default-rule-path: "/opt/sng/ips/rules""#),
            "{t}"
        );
        assert!(t.contains(r#"  - "staged.rules""#), "{t}");
    }

    #[test]
    fn render_emits_eve_and_stats_outputs() {
        let mut input = baseline();
        input.eve_log_path = PathBuf::from("/var/log/sng/eve.json");
        input.stats_socket_path = PathBuf::from("/run/sng/suricata.sock");
        let cfg = ConfigGenerator::new().render(&input).unwrap();
        let t = cfg.text();
        assert!(t.contains(r#"filename: "/var/log/sng/eve.json""#), "{t}");
        assert!(t.contains(r#"filename: "/run/sng/suricata.sock""#), "{t}");
        // Every EVE type the manager normalises must be enabled
        // in the outputs stanza.
        for ty in ["alert", "anomaly", "dns", "http", "tls", "flow", "fileinfo"] {
            assert!(t.contains(&format!("- {ty}\n")), "{t} missing type {ty}");
        }
    }

    #[test]
    fn render_emits_app_layer_parsers_in_sorted_order() {
        let mut input = baseline();
        input.app_layer_enabled.clear();
        input.app_layer_enabled.insert("tls".into(), true);
        input.app_layer_enabled.insert("http".into(), false);
        input.app_layer_enabled.insert("dns".into(), true);
        let cfg = ConfigGenerator::new().render(&input).unwrap();
        let t = cfg.text();
        // BTreeMap keeps keys sorted, so iteration order is
        // deterministic regardless of insertion order. The test
        // pins the order to defend against an accidental switch
        // to a HashMap.
        let dns_pos = t.find("    dns:\n      enabled: yes").unwrap();
        let http_pos = t.find("    http:\n      enabled: no").unwrap();
        let tls_pos = t.find("    tls:\n      enabled: yes").unwrap();
        assert!(dns_pos < http_pos, "{t}");
        assert!(http_pos < tls_pos, "{t}");
    }

    #[test]
    fn render_is_byte_deterministic_for_identical_inputs() {
        let g = ConfigGenerator::new();
        let a = g.render(&baseline()).unwrap();
        let b = g.render(&baseline()).unwrap();
        assert_eq!(a.text(), b.text());
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn render_changes_digest_when_interface_changes() {
        let mut input1 = baseline();
        input1.interface = "eth0".into();
        let mut input2 = baseline();
        input2.interface = "eth1".into();
        let g = ConfigGenerator::new();
        let cfg1 = g.render(&input1).unwrap();
        let cfg2 = g.render(&input2).unwrap();
        assert_ne!(cfg1.digest(), cfg2.digest());
    }

    #[test]
    fn render_rejects_empty_interface() {
        let mut input = baseline();
        input.interface = String::new();
        let err = ConfigGenerator::new().render(&input).unwrap_err();
        match err {
            IpsError::Config(m) => assert!(m.contains("interface")),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_interface_with_control_char() {
        let mut input = baseline();
        input.interface = "eth0\nfoo".into();
        let err = ConfigGenerator::new().render(&input).unwrap_err();
        assert!(matches!(err, IpsError::Config(_)));
    }

    #[test]
    fn render_rejects_quote_in_home_net() {
        // YAML writer cannot safely escape a literal `"` in the
        // bracketed-list shape it emits — better to surface a
        // structured error than to write a malformed file.
        let mut input = baseline();
        input.home_net.push(r#"10.0.0.0/8" injection"#.into());
        let err = ConfigGenerator::new().render(&input).unwrap_err();
        assert!(matches!(err, IpsError::Config(_)));
    }

    #[test]
    fn render_rejects_backslash_in_paths() {
        let mut input = baseline();
        input.rule_file_path = PathBuf::from(r"/etc/suricata\bad");
        let err = ConfigGenerator::new().render(&input).unwrap_err();
        assert!(matches!(err, IpsError::Config(_)));
    }

    #[test]
    fn render_max_pending_packets_renders_only_when_set() {
        let mut input = baseline();
        input.max_pending_packets = Some(2048);
        let with_set = ConfigGenerator::new().render(&input).unwrap();
        assert!(with_set.text().contains("max-pending-packets: 2048"));
        input.max_pending_packets = None;
        let without = ConfigGenerator::new().render(&input).unwrap();
        assert!(!without.text().contains("max-pending-packets:"));
    }

    #[test]
    fn digest_hex_is_64_lowercase_chars() {
        let cfg = ConfigGenerator::new().render(&baseline()).unwrap();
        let h = cfg.digest_hex();
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn defaults_inline_enables_drop_and_ips_mode() {
        let i = IpsConfigInput::defaults(IpsRuntime::Inline);
        assert_eq!(i.runtime, IpsRuntime::Inline);
        assert!(i.app_layer_enabled["tls"]);
        assert!(i.app_layer_enabled["http"]);
        assert!(i.app_layer_enabled["dns"]);
    }

    #[test]
    fn defaults_ids_does_not_force_drop() {
        let i = IpsConfigInput::defaults(IpsRuntime::Ids);
        assert_eq!(i.runtime, IpsRuntime::Ids);
        assert_eq!(i.force_drop_on_alert, None);
    }

    #[test]
    fn parent_or_root_falls_back_to_root_for_filename_only_path() {
        // file_name-only paths report no parent → should fall
        // back to "/" rather than panic.
        assert_eq!(parent_or_root(std::path::Path::new("sng.rules")), "/");
    }

    #[test]
    fn file_name_returns_basename_or_empty() {
        assert_eq!(file_name(std::path::Path::new("/a/b/c.rules")), "c.rules");
        assert_eq!(file_name(std::path::Path::new("/")), "");
    }

    #[test]
    fn join_quoted_handles_empty_list() {
        assert_eq!(join_quoted(&[]), "[]");
    }

    #[test]
    fn join_quoted_comma_joins_entries() {
        assert_eq!(
            join_quoted(&["10.0.0.0/8".into(), "192.168.0.0/16".into()]),
            "[10.0.0.0/8,192.168.0.0/16]"
        );
    }
}
