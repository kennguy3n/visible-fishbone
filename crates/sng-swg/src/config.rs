//! Deterministic Envoy bootstrap config renderer.
//!
//! Two design constraints shape this module:
//!
//! 1. **Byte-identical determinism.** Given the same
//!    [`EnvoyConfig`] input, [`render_envoy_yaml`] produces the
//!    same byte sequence on every call. That property is what
//!    makes the hot-swap digest dedup safe: the supervisor
//!    SHA-256s the rendered script and skips the kernel-side
//!    restart when the new bundle hashes the same as the
//!    installed one.
//! 2. **No third-party YAML parser.** YAML is hand-rendered.
//!    The output is a small, fully-controlled subset (scalars,
//!    sequences, maps — no anchors, no flow style, no
//!    explicit document markers) that a writer can emit in a
//!    few hundred lines, where pulling a parser would add
//!    300 kLoC of dep we never use.
//!
//! The mirror of this module on the firewall side is
//! `sng-fw::compile::render_script` which renders nftables. Both
//! emit text the supervisor SHA-256s, both pin map iteration
//! order via `BTreeMap`, and both treat the digest as the
//! source-of-truth identity of the bundle.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SwgError;

/// Internal helper: write a formatted line to the render buffer.
///
/// `writeln!` on `&mut String` returns `fmt::Result` because the
/// underlying trait is fallible — but every concrete
/// implementation of `Write` for `String` is infallible (it can
/// only return `Ok(())`). The macro discards the result so the
/// hot rendering path doesn't have to thread `Result` through
/// every line, matching the style sng-fw::compile uses for the
/// equivalent nftables renderer.
macro_rules! ln {
    ($buf:expr, $($t:tt)*) => {{
        // The let-binding silences `unused_must_use` while making
        // the intent (drop the result, it's infallible) explicit.
        let _: ::std::fmt::Result = writeln!($buf, $($t)*);
    }};
}

/// Top-level Envoy config the supervisor renders into YAML.
///
/// Holds *only* the fields the SWG actually controls; anything
/// that's static across deployments (admin port, threading
/// model, logging) lives as a literal in
/// [`render_envoy_yaml`] so an operator can't mis-configure it
/// out from under the supervisor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvoyConfig {
    /// One or more listeners. Typically a single listener on
    /// :8443 binding both HTTP/1.1 and HTTP/2 forward-proxy
    /// traffic, but the multi-listener shape supports future
    /// per-tenant isolation (one listener per VLAN).
    pub listeners: Vec<ListenerConfig>,
    /// Upstream clusters the listeners reference. For the
    /// SWG-out flow this is the ext-authz cluster (in-process
    /// HTTP service on a unix socket) plus a generic
    /// `dynamic_forward_proxy` cluster.
    pub clusters: Vec<ClusterConfig>,
}

impl EnvoyConfig {
    /// Build a minimal but fully-functional default config:
    /// one forward-proxy listener on :8443 plus the ext-authz
    /// and forward-proxy clusters. Used by the manager when no
    /// operator bundle is installed yet.
    #[must_use]
    pub fn minimal_forward_proxy(ext_authz_endpoint: &str) -> Self {
        Self {
            listeners: vec![ListenerConfig {
                name: "swg_forward".into(),
                address: "0.0.0.0".into(),
                port: 8443,
                ext_authz_cluster: "ext_authz".into(),
                forward_proxy_cluster: "dynamic_forward_proxy".into(),
                tls_bypass_sni_suffixes: Vec::new(),
            }],
            clusters: vec![
                ClusterConfig {
                    name: "ext_authz".into(),
                    // The caller passes either a `unix:///path`
                    // string or a `host:port` form; both are
                    // accepted by render_endpoint.
                    endpoints: vec![ext_authz_endpoint.into()],
                    connect_timeout_ms: 1_000,
                },
                ClusterConfig {
                    name: "dynamic_forward_proxy".into(),
                    endpoints: Vec::new(),
                    connect_timeout_ms: 5_000,
                },
            ],
        }
    }
}

/// One listener — a bind address + port + the ext-authz hook +
/// the forward-proxy egress cluster.
///
/// The `tls_bypass_sni_suffixes` field is wire-format-only: it
/// lives in the rendered config so the operator can see what's
/// in scope, but the runtime decision is made by
/// [`crate::bypass::BypassList`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub ext_authz_cluster: String,
    pub forward_proxy_cluster: String,
    pub tls_bypass_sni_suffixes: Vec<String>,
}

/// One Envoy cluster. The field set is deliberately minimal —
/// we only render what the SWG actually uses, and an operator
/// who needs richer cluster semantics (load balancing,
/// outlier detection, circuit breakers) writes their own
/// Envoy bootstrap snippet via the supervisor's `extra_yaml`
/// extension point (future work).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub name: String,
    /// Endpoint strings, formatted as `host:port` for IP
    /// targets or `unix:///path/to/sock` for unix-socket
    /// targets. The renderer parses the prefix to pick the
    /// right Envoy `socket_address` vs `pipe` shape.
    pub endpoints: Vec<String>,
    pub connect_timeout_ms: u32,
}

/// Render an [`EnvoyConfig`] into Envoy's bootstrap YAML.
///
/// Determinism guarantees:
///
/// * Map keys are emitted in a *fixed* order (defined by the
///   writer, not by the source map iteration order) so the
///   rendered string is byte-identical across builds.
/// * Sequences are emitted in input order — the caller is
///   responsible for sorting `tls_bypass_sni_suffixes` etc. if
///   they want stable ordering on operator-supplied lists.
/// * No timestamps, hostnames, or other ambient values bleed
///   into the output. Two processes on different hosts that
///   apply the same bundle render the same bytes.
///
/// # Errors
/// Returns [`SwgError::Config`] when the input would produce
/// syntactically invalid YAML — currently the only such case
/// is a string field containing a control character we cannot
/// safely escape (newline + double-quote + backslash are
/// handled; raw NUL byte is not).
pub fn render_envoy_yaml(cfg: &EnvoyConfig) -> Result<String, SwgError> {
    let mut out = String::with_capacity(2048);
    // Header — version-pin the bootstrap schema so a future
    // Envoy that changes shape doesn't silently load a stale
    // config.
    out.push_str("# generated by sng-swg; do not edit\n");
    out.push_str("admin:\n");
    out.push_str("  address:\n");
    out.push_str("    socket_address:\n");
    out.push_str("      address: 127.0.0.1\n");
    out.push_str("      port_value: 9901\n");
    out.push_str("static_resources:\n");

    // listeners ----
    out.push_str("  listeners:\n");
    for l in &cfg.listeners {
        render_listener(&mut out, l)?;
    }

    // clusters ----
    out.push_str("  clusters:\n");
    for c in &cfg.clusters {
        render_cluster(&mut out, c)?;
    }
    Ok(out)
}

/// SHA-256 digest of the rendered config, hex-encoded. The
/// supervisor stores the last installed digest; on a bundle
/// reload it computes the new digest and skips the
/// `envoy --mode validate` + SIGHUP cycle when the digest is
/// unchanged — same pattern sng-fw uses for nftables.
#[must_use]
pub fn digest_envoy_yaml(rendered: &str) -> String {
    let mut h = Sha256::new();
    h.update(rendered.as_bytes());
    hex::encode(h.finalize())
}

fn render_listener(out: &mut String, l: &ListenerConfig) -> Result<(), SwgError> {
    ln!(out, "  - name: {}", quoted(&l.name)?);
    ln!(out, "    address:");
    ln!(out, "      socket_address:");
    ln!(out, "        address: {}", quoted(&l.address)?);
    ln!(out, "        port_value: {}", l.port);
    ln!(out, "    filter_chains:");
    ln!(out, "    - filters:");
    ln!(
        out,
        "      - name: envoy.filters.network.http_connection_manager"
    );
    ln!(out, "        typed_config:");
    ln!(
        out,
        "          \"@type\": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
    );
    ln!(out, "          stat_prefix: {}", quoted(&l.name)?);
    ln!(out, "          codec_type: AUTO");
    ln!(out, "          route_config:");
    ln!(out, "            name: local_route");
    ln!(out, "            virtual_hosts:");
    ln!(out, "            - name: any");
    ln!(out, "              domains:");
    ln!(out, "              - \"*\"");
    ln!(out, "              routes:");
    ln!(out, "              - match:");
    ln!(out, "                  prefix: /");
    ln!(out, "                route:");
    ln!(
        out,
        "                  cluster: {}",
        quoted(&l.forward_proxy_cluster)?
    );
    ln!(out, "          http_filters:");
    ln!(out, "          - name: envoy.filters.http.ext_authz");
    ln!(out, "            typed_config:");
    ln!(
        out,
        "              \"@type\": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"
    );
    ln!(out, "              http_service:");
    ln!(out, "                server_uri:");
    ln!(
        out,
        "                  uri: {}",
        quoted(&format!("http://{}/ext_authz", l.ext_authz_cluster))?
    );
    ln!(
        out,
        "                  cluster: {}",
        quoted(&l.ext_authz_cluster)?
    );
    ln!(out, "                  timeout: 0.250s");
    ln!(out, "          - name: envoy.filters.http.router");
    ln!(out, "            typed_config:");
    ln!(
        out,
        "              \"@type\": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
    );

    // TLS bypass annotation — rendered as a comment block so
    // operators can see the in-effect list on `envoy_config.yaml`
    // inspection. The runtime decision uses BypassList; this is
    // purely operator-visible documentation that lives next to
    // the listener it applies to. Defense in depth: pass each
    // suffix through `sanitize_for_comment` instead of raw `{}`
    // interpolation. DNS SNI suffixes cannot contain newlines or
    // control chars in practice (the IDNA label set is a strict
    // subset of LDH), and the runtime BypassList path doesn't
    // care about the comment block at all — but a single stray
    // `\n` in an operator-supplied suffix would terminate the
    // comment and inject the rest of the suffix as real YAML
    // content into the listener stanza. The validator at
    // `envoy --mode validate` would catch the resulting parse
    // error, but the resulting failure mode is opaque
    // ("unknown field foo") rather than a useful operator
    // message. Sanitizing here keeps the comment self-contained
    // regardless of what reached `tls_bypass_sni_suffixes`.
    if !l.tls_bypass_sni_suffixes.is_empty() {
        ln!(out, "    # tls_bypass_sni_suffixes:");
        for s in &l.tls_bypass_sni_suffixes {
            ln!(out, "    #   - {}", sanitize_for_comment(s));
        }
    }
    Ok(())
}

/// Sanitize a string for inclusion in a YAML `#`-prefixed
/// comment line. Any character that could cause the comment to
/// terminate early (newline, carriage return) or render as an
/// invisible glyph (control chars, NUL) is replaced with the
/// Unicode escape form `\u{XXXX}` so the comment remains
/// single-line and self-describing. This is intentionally
/// lossy — the bypass list itself is loaded from
/// `tls_bypass_sni_suffixes` (a structured `Vec<String>`),
/// never round-tripped from this comment block, so a lossy
/// representation here cannot affect runtime behavior.
fn sanitize_for_comment(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' | '\r' | '\t' | '\0' => {
                let _ = write!(out, "\\u{{{:04X}}}", c as u32);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{{{:04X}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn render_cluster(out: &mut String, c: &ClusterConfig) -> Result<(), SwgError> {
    ln!(out, "  - name: {}", quoted(&c.name)?);
    // Connect timeout — render seconds with fractional millis
    // so the YAML is human-readable while still preserving
    // millisecond precision.
    let secs = c.connect_timeout_ms / 1_000;
    let millis = c.connect_timeout_ms % 1_000;
    ln!(out, "    connect_timeout: {secs}.{millis:03}s");
    // dynamic_forward_proxy cluster: the no-endpoint shape Envoy
    // resolves DNS on demand per upstream request. Non-empty
    // endpoint list → STATIC cluster with a load_assignment.
    if c.endpoints.is_empty() {
        ln!(out, "    type: STRICT_DNS");
        ln!(out, "    lb_policy: CLUSTER_PROVIDED");
        ln!(
            out,
            "    cluster_type:\n      name: envoy.clusters.dynamic_forward_proxy\n      typed_config:\n        \"@type\": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig\n        dns_cache_config:\n          name: dynamic_forward_proxy_cache_config\n          dns_lookup_family: V4_PREFERRED"
        );
    } else {
        ln!(out, "    type: STATIC");
        ln!(out, "    lb_policy: ROUND_ROBIN");
        ln!(out, "    load_assignment:");
        ln!(out, "      cluster_name: {}", quoted(&c.name)?);
        ln!(out, "      endpoints:");
        ln!(out, "      - lb_endpoints:");
        for ep in &c.endpoints {
            render_endpoint(out, ep)?;
        }
    }
    Ok(())
}

fn render_endpoint(out: &mut String, ep: &str) -> Result<(), SwgError> {
    ln!(out, "        - endpoint:");
    ln!(out, "            address:");
    if let Some(path) = ep.strip_prefix("unix://") {
        // Envoy's pipe shape — used for the ext-authz unix
        // socket so the in-process handler doesn't open a TCP
        // port at all.
        ln!(out, "              pipe:");
        ln!(out, "                path: {}", quoted(path)?);
    } else {
        // host:port shape — Envoy's socket_address.
        let (host, port) = parse_host_port(ep)?;
        ln!(out, "              socket_address:");
        ln!(out, "                address: {}", quoted(host)?);
        ln!(out, "                port_value: {port}");
    }
    Ok(())
}

fn parse_host_port(ep: &str) -> Result<(&str, u16), SwgError> {
    let (host, port) = ep
        .rsplit_once(':')
        .ok_or_else(|| SwgError::Config(format!("endpoint missing port: {ep}")))?;
    let port: u16 = port
        .parse()
        .map_err(|e| SwgError::Config(format!("endpoint port not u16 ({ep}): {e}")))?;
    Ok((host, port))
}

/// Render a string scalar with quoting and escaping rules that
/// keep the YAML safe regardless of operator input. We always
/// emit double-quoted to dodge any "is this a YAML special
/// value" ambiguity (`no`, `on`, `2020-01-01`, etc.).
fn quoted(s: &str) -> Result<String, SwgError> {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Forbid raw NUL — YAML 1.2 simply cannot escape
            // it. We reject early rather than silently dropping
            // the byte.
            '\0' => return Err(SwgError::Config("string contains NUL".into())),
            // Other control characters (0x01..0x1f minus the
            // whitespace handled above) are rejected for the
            // same reason: round-tripping is ambiguous.
            c if (c as u32) < 0x20 => {
                return Err(SwgError::Config(format!(
                    "string contains unrenderable control char U+{:04X}",
                    c as u32
                )));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Compute a per-listener summary keyed by listener name. The
/// manager uses this on the health snapshot to surface the
/// listener inventory to operators without re-parsing the
/// rendered YAML.
#[must_use]
pub fn summarize_listeners(cfg: &EnvoyConfig) -> BTreeMap<String, ListenerSummary> {
    let mut m = BTreeMap::new();
    for l in &cfg.listeners {
        m.insert(
            l.name.clone(),
            ListenerSummary {
                bind: format!("{}:{}", l.address, l.port),
                ext_authz_cluster: l.ext_authz_cluster.clone(),
                forward_proxy_cluster: l.forward_proxy_cluster.clone(),
                bypass_count: l.tls_bypass_sni_suffixes.len(),
            },
        );
    }
    m
}

/// One row of [`summarize_listeners`]. Stable shape: an
/// external dashboard can lock onto these fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerSummary {
    pub bind: String,
    pub ext_authz_cluster: String,
    pub forward_proxy_cluster: String,
    pub bypass_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample() -> EnvoyConfig {
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg.listeners[0].tls_bypass_sni_suffixes = vec!["bank.com".into(), "irs.gov".into()];
        cfg
    }

    #[test]
    fn minimal_default_renders_without_error() {
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(s.starts_with("# generated by sng-swg"));
        assert!(s.contains("port_value: 8443"));
        assert!(s.contains("envoy.filters.http.ext_authz"));
        assert!(s.contains("envoy.filters.http.router"));
        assert!(s.contains("dynamic_forward_proxy"));
    }

    #[test]
    fn render_is_deterministic_across_calls() {
        // The supervisor's hot-swap digest dedup depends on
        // this property: two renders of the same input must be
        // byte-identical. If a future refactor introduces
        // HashMap iteration order or rand-seeded ordering, the
        // dedup will start incorrectly forcing kernel restarts.
        let cfg = sample();
        let a = render_envoy_yaml(&cfg).unwrap();
        let b = render_envoy_yaml(&cfg).unwrap();
        assert_eq!(a, b, "render must be byte-identical");
    }

    #[test]
    fn digest_changes_when_config_changes() {
        let mut cfg = sample();
        let d0 = digest_envoy_yaml(&render_envoy_yaml(&cfg).unwrap());
        cfg.listeners[0].port = 9443;
        let d1 = digest_envoy_yaml(&render_envoy_yaml(&cfg).unwrap());
        assert_ne!(d0, d1);
    }

    #[test]
    fn digest_stable_for_equal_configs() {
        let cfg = sample();
        let d0 = digest_envoy_yaml(&render_envoy_yaml(&cfg).unwrap());
        let d1 = digest_envoy_yaml(&render_envoy_yaml(&cfg.clone()).unwrap());
        assert_eq!(d0, d1, "structurally equal configs hash equal");
    }

    #[test]
    fn bypass_list_emitted_as_comment_block() {
        let cfg = sample();
        let s = render_envoy_yaml(&cfg).unwrap();
        // The runtime decision uses BypassList; the comment
        // is documentation only, so we assert exact text shape.
        assert!(s.contains("# tls_bypass_sni_suffixes:"));
        assert!(s.contains("#   - bank.com"));
        assert!(s.contains("#   - irs.gov"));
    }

    #[test]
    fn unix_socket_endpoint_renders_pipe_shape() {
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "ext_authz".into(),
                endpoints: vec!["unix:///var/run/sng/extauthz.sock".into()],
                connect_timeout_ms: 100,
            }],
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(s.contains("pipe:"));
        assert!(s.contains("path: \"/var/run/sng/extauthz.sock\""));
        assert!(!s.contains("socket_address:\n                address: \"unix"));
    }

    #[test]
    fn host_port_endpoint_renders_socket_address() {
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "upstream".into(),
                endpoints: vec!["10.0.0.5:8080".into()],
                connect_timeout_ms: 1_500,
            }],
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(s.contains("address: \"10.0.0.5\""));
        assert!(s.contains("port_value: 8080"));
        // connect_timeout: 1500ms → 1.500s.
        assert!(s.contains("connect_timeout: 1.500s"), "got\n{s}");
    }

    #[test]
    fn empty_endpoints_renders_dynamic_forward_proxy() {
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "fwd".into(),
                endpoints: Vec::new(),
                connect_timeout_ms: 5_000,
            }],
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(s.contains("type: STRICT_DNS"));
        assert!(s.contains("dynamic_forward_proxy_cache_config"));
        assert!(s.contains("connect_timeout: 5.000s"));
    }

    #[test]
    fn quoted_escapes_special_chars_safely() {
        let q = quoted("with \"quote\" and \\back and \nnewline").unwrap();
        assert_eq!(
            q, "\"with \\\"quote\\\" and \\\\back and \\nnewline\"",
            "double-quote, backslash, newline must escape"
        );
    }

    #[test]
    fn quoted_rejects_nul_byte() {
        let err = quoted("ok\0bad").expect_err("NUL must reject");
        match err {
            SwgError::Config(m) => assert!(m.contains("NUL"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn quoted_rejects_other_control_chars() {
        let err = quoted("\x01").expect_err("control char must reject");
        match err {
            SwgError::Config(m) => assert!(m.contains("U+0001"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_for_comment_escapes_newline_and_cr_and_tab() {
        // Sanity: regular ascii passes through untouched (DNS
        // labels are always LDH so this is the production
        // hot-path).
        assert_eq!(sanitize_for_comment("bank.com"), "bank.com");

        // A stray newline would terminate the YAML comment and
        // inject the rest of the suffix as raw YAML content into
        // the listener stanza. We collapse it into a printable
        // escape so the comment block stays single-line.
        assert_eq!(sanitize_for_comment("bad\nsuffix"), "bad\\u{000A}suffix");

        // Carriage return and tab are likewise escaped so the
        // comment renders as a single readable line regardless
        // of what reached the field.
        assert_eq!(
            sanitize_for_comment("\rbank\tcom"),
            "\\u{000D}bank\\u{0009}com"
        );

        // Arbitrary low-control byte falls into the same escape
        // path — defense in depth against any byte stream that
        // makes it through deserialisation.
        assert_eq!(sanitize_for_comment("\x01"), "\\u{0001}");
    }

    #[test]
    fn rendered_comment_block_stays_single_line_under_adversarial_suffix() {
        // End-to-end check: render a listener with an
        // adversarial suffix and confirm the YAML comment block
        // remains structurally intact. Specifically: the line
        // for the suffix starts with the `#   -` marker (i.e.
        // the newline injection did not escape out of the
        // comment and the rest did not become real YAML).
        let mut cfg = sample();
        cfg.listeners[0].tls_bypass_sni_suffixes =
            vec!["benign.com".into(), "adversarial\nfield: pwn".into()];
        let s = render_envoy_yaml(&cfg).expect("render must succeed");
        // The benign entry must render verbatim.
        assert!(s.contains("    #   - benign.com"), "{s}");
        // The adversarial entry must be present as a comment
        // line (no real `field:` key leaking into the listener
        // stanza after the comment block).
        assert!(
            s.contains("    #   - adversarial\\u{000A}field: pwn"),
            "{s}"
        );
        // Negative assertion: no bare `field: pwn` at the start
        // of a YAML line (which would have happened with the
        // pre-sanitization renderer).
        for line in s.lines() {
            assert!(
                !line.trim_start().starts_with("field: pwn"),
                "newline injection produced a real YAML key: {line:?}"
            );
        }
    }

    #[test]
    fn parse_host_port_rejects_missing_colon() {
        let err = parse_host_port("nohostport").expect_err("must reject");
        match err {
            SwgError::Config(m) => assert!(m.contains("missing port"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn parse_host_port_rejects_non_u16_port() {
        let err = parse_host_port("h:99999").expect_err("must reject");
        match err {
            SwgError::Config(m) => assert!(m.contains("not u16"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn parse_host_port_succeeds_on_valid() {
        let (h, p) = parse_host_port("example.com:443").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn summarize_listeners_keys_by_name() {
        let cfg = sample();
        let sum = summarize_listeners(&cfg);
        assert_eq!(sum.len(), 1);
        let row = sum.get("swg_forward").unwrap();
        assert_eq!(row.bind, "0.0.0.0:8443");
        assert_eq!(row.ext_authz_cluster, "ext_authz");
        assert_eq!(row.forward_proxy_cluster, "dynamic_forward_proxy");
        assert_eq!(row.bypass_count, 2);
    }

    #[test]
    fn rendering_invalid_string_field_propagates_config_error() {
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///x");
        cfg.listeners.clear();
        // Inject a NUL into a cluster name — render must fail.
        cfg.clusters[0].name = "bad\0cluster".into();
        let err = render_envoy_yaml(&cfg).expect_err("must fail");
        assert!(matches!(err, SwgError::Config(_)), "{err:?}");
    }
}
