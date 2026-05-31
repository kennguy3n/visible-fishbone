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

/// Default Envoy admin port. Shared with
/// [`crate::process::ShellEnvoy::new`] so a caller that
/// constructs both with their default values does not produce
/// a renderer/supervisor port mismatch.
pub const DEFAULT_ADMIN_PORT: u16 = 9901;

/// Default per-request ext-authz timeout, in milliseconds.
///
/// 250 ms is generous for the in-process providers sng-swg
/// ships at launch ([`crate::categorizer::LocalCategoryDb`] +
/// [`crate::malware::StaticMalwareList`]) where the verdict
/// path is microsecond-level work over an `ArcSwap` snapshot.
/// Remote providers (Cisco Talos, custom HTTPS feeds, managed
/// verdict services) typically need a larger budget; operators
/// configuring such a provider should raise
/// [`ListenerConfig::ext_authz_timeout_ms`] to at least the 99th-
/// percentile latency of the upstream, otherwise Envoy will
/// fail-closed deny every request whose verdict overruns this
/// window.
pub const DEFAULT_EXT_AUTHZ_TIMEOUT_MS: u32 = 250;

/// Free function returning [`DEFAULT_EXT_AUTHZ_TIMEOUT_MS`], used
/// as the [`ListenerConfig::ext_authz_timeout_ms`]
/// `#[serde(default)]` helper.
///
/// The field was added after the wire format already shipped, so
/// older persisted bundles do *not* carry an
/// `ext_authz_timeout_ms` key. Without a serde default the
/// missing field would fail deserialisation with
/// `missing field `ext_authz_timeout_ms``, which would break
/// every round-trip path the control plane has for stored
/// bundles (cache reload, replay log, on-disk bundle store, any
/// external bundle producer that hasn't been re-rendered against
/// the new schema). Surfacing this as a typed default keeps the
/// wire format forward-compatible: an older producer's bundle
/// loads at the historical hardcoded 250 ms timeout, exactly as
/// it would have rendered before the field existed.
#[must_use]
fn default_ext_authz_timeout_ms() -> u32 {
    DEFAULT_EXT_AUTHZ_TIMEOUT_MS
}

/// Top-level Envoy config the supervisor renders into YAML.
///
/// Holds *only* the fields the SWG actually controls; anything
/// that's static across deployments (threading model, logging)
/// lives as a literal in [`render_envoy_yaml`] so an operator
/// can't mis-configure it out from under the supervisor.
///
/// # Admin-port consistency
///
/// [`Self::admin_port`] **must** match the
/// [`crate::process::ShellEnvoy::admin_port`] the supervisor
/// healthcheck probes. The renderer emits whatever the field
/// holds; the supervisor probes whatever `ShellEnvoy` was
/// constructed with. The wiring layer is responsible for
/// passing the same value to both (e.g. derive `ShellEnvoy`'s
/// admin port from `EnvoyConfig::admin_port` at construction).
/// [`EnvoyConfig::minimal_forward_proxy`] and the [`Default`]
/// initialiser for `ShellEnvoy` both pick
/// [`DEFAULT_ADMIN_PORT`] so callers using the defaults are
/// safe; an operator that overrides one must override the
/// other.
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
    /// TCP port the Envoy admin endpoint binds on `127.0.0.1`.
    /// The supervisor's healthcheck must probe this port. Defaults
    /// to [`DEFAULT_ADMIN_PORT`]. See the struct doc on
    /// admin-port consistency.
    pub admin_port: u16,
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
                ext_authz_timeout_ms: DEFAULT_EXT_AUTHZ_TIMEOUT_MS,
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
            admin_port: DEFAULT_ADMIN_PORT,
        }
    }

    /// Override the admin port. Use in tandem with
    /// [`crate::process::ShellEnvoy::with_admin_port`] so the
    /// rendered config and the supervisor healthcheck agree.
    #[must_use]
    pub fn with_admin_port(mut self, port: u16) -> Self {
        self.admin_port = port;
        self
    }
}

/// One listener — a bind address + port + the ext-authz hook +
/// the forward-proxy egress cluster.
///
/// The `tls_bypass_sni_suffixes` field is wire-format-only: it
/// lives in the rendered config so the operator can see what's
/// in scope, but the runtime decision is made by
/// [`crate::bypass::BypassList`].
///
/// `ext_authz_timeout_ms` is the per-request timeout the rendered
/// Envoy YAML stamps on the `envoy.filters.http.ext_authz`
/// HTTP-service block. With the in-process providers sng-swg
/// ships today (`LocalCategoryDb` + `StaticMalwareList`) the
/// verdict path is microsecond-level so the
/// [`DEFAULT_EXT_AUTHZ_TIMEOUT_MS`] default of 250 ms is
/// generous. A future remote provider (Cisco Talos, custom HTTPS
/// feed, managed verdict service) can need longer — exposing the
/// timeout as a per-listener field is what lets an operator dial
/// it up without forking the renderer. Envoy interprets the
/// rendered value as a fail-closed deny on expiry, so under-sizing
/// it for a slow upstream causes Envoy to deny every request; the
/// hardcoded 250 ms is therefore the wrong default to bake in at
/// the wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub ext_authz_cluster: String,
    pub forward_proxy_cluster: String,
    pub tls_bypass_sni_suffixes: Vec<String>,
    /// Per-request timeout, in milliseconds, stamped on the
    /// rendered Envoy `ext_authz` HTTP service block. Rendered as
    /// `<seconds>s` (e.g. `0.250s`, `1.500s`, `5s`). Set to a
    /// value at least as large as the worst-case verdict latency
    /// of the configured `UrlCategorizer` /
    /// `MalwareVerdictProvider`. Defaults to
    /// [`DEFAULT_EXT_AUTHZ_TIMEOUT_MS`] (250 ms).
    ///
    /// # Zero is rejected at render time
    ///
    /// Envoy's protobuf `Duration` parser reads `0s` as
    /// *"disabled"* — the ext-authz call would have **no**
    /// timeout, so a hung verdict provider would stall every
    /// in-flight request indefinitely rather than tripping
    /// Envoy's fail-closed deny. Because sng-swg's whole reason
    /// for sitting in front of Envoy is to fail-closed when the
    /// verdict pipeline is unhealthy, a zero value is a
    /// foot-gun: a typo in a persisted bundle
    /// (`ext_authz_timeout_ms: 0`), a default-initialised struct
    /// literal, or a careless field elision would silently widen
    /// the timeout to "no timeout" with no operator-visible
    /// signal. [`render_envoy_yaml`] therefore rejects
    /// `ext_authz_timeout_ms == 0` as [`SwgError::Config`] at
    /// install time. Operators who genuinely want unbounded
    /// verdict latency must do it explicitly via an extension
    /// point we do not currently expose, rather than by leaving
    /// this field zero.
    #[serde(default = "default_ext_authz_timeout_ms")]
    pub ext_authz_timeout_ms: u32,
}

/// One Envoy cluster. The field set is deliberately minimal —
/// we only render what the SWG actually uses, and an operator
/// who needs richer cluster semantics (load balancing,
/// outlier detection, circuit breakers) writes their own
/// Envoy bootstrap snippet via the supervisor's `extra_yaml`
/// extension point (future work).
///
/// # `connect_timeout_ms` zero is rejected at render time
///
/// Envoy's protobuf `Duration` parser reads `0s` as "no
/// timeout" on cluster `connect_timeout`. For a STATIC cluster
/// (`endpoints` non-empty) a zero connect timeout means Envoy
/// will wait *indefinitely* for the TCP connect to succeed,
/// pinning the worker thread on a black-holed upstream. For an
/// endpointless `dynamic_forward_proxy` cluster Envoy still
/// honours `connect_timeout` on the per-request DNS-resolved
/// upstream socket connect, so the same hang applies. This is
/// the symmetric foot-gun to
/// [`ListenerConfig::ext_authz_timeout_ms`] — a zero in either
/// timeout slot is a configuration we never want to render to
/// disk. [`render_envoy_yaml`] therefore rejects
/// `connect_timeout_ms == 0` as [`SwgError::Config`] at install
/// time, naming the offending cluster.
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
    // Reject the fail-closed-disable foot-gun before we touch
    // the output buffer. Envoy reads `0s` as "no timeout"; a
    // zero on a fail-closed-deny gate is exactly the
    // configuration we never want to render to disk. See the
    // `ListenerConfig::ext_authz_timeout_ms` doc for the
    // failure mode this prevents.
    for l in &cfg.listeners {
        if l.ext_authz_timeout_ms == 0 {
            return Err(SwgError::Config(format!(
                "listener {:?} has ext_authz_timeout_ms = 0, which Envoy interprets \
                 as \"disabled\"; sng-swg requires a positive timeout so the \
                 ext_authz hop preserves fail-closed deny on verdict-provider hangs",
                l.name
            )));
        }
    }
    // Symmetric guard for cluster `connect_timeout`: Envoy reads
    // `0s` here as "no timeout" on the upstream TCP connect
    // (`dynamic_forward_proxy` clusters still honour this on the
    // per-request DNS-resolved socket connect, so the carve-out
    // for endpoint-less clusters does not apply). A zero would
    // let a black-holed upstream pin the worker thread
    // indefinitely on connect, defeating the whole point of
    // having a connect-time budget. Reject at install time and
    // name the offending cluster.
    for c in &cfg.clusters {
        if c.connect_timeout_ms == 0 {
            return Err(SwgError::Config(format!(
                "cluster {:?} has connect_timeout_ms = 0, which Envoy interprets \
                 as \"no timeout\" on the upstream TCP connect; sng-swg requires \
                 a positive connect timeout so a black-holed upstream cannot \
                 pin worker threads indefinitely on connect",
                c.name
            )));
        }
    }
    let mut out = String::with_capacity(2048);
    // Header — version-pin the bootstrap schema so a future
    // Envoy that changes shape doesn't silently load a stale
    // config.
    out.push_str("# generated by sng-swg; do not edit\n");
    out.push_str("admin:\n");
    out.push_str("  address:\n");
    out.push_str("    socket_address:\n");
    out.push_str("      address: 127.0.0.1\n");
    // Bind whatever port the operator wired into the config.
    // Mirrored against `ShellEnvoy::admin_port` by the wiring
    // layer so the supervisor's healthcheck reaches the bound
    // port; see the [`EnvoyConfig`] doc on admin-port
    // consistency.
    ln!(out, "      port_value: {}", cfg.admin_port);
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
    ln!(
        out,
        "                  timeout: {}",
        format_envoy_seconds(l.ext_authz_timeout_ms)
    );
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
    // Connect timeout — route through `format_envoy_seconds` so
    // both protobuf-Duration slots in the rendered YAML
    // (`connect_timeout` here, `timeout` in the ext_authz HTTP
    // service block) emit the same canonical form. Two
    // independent formatters in the same renderer would let a
    // future schema change on one path silently diverge from the
    // other, and would split the digest-dedup hash space
    // unnecessarily (`5.000s` vs `5s` hash to different
    // outputs even though Envoy reads them identically).
    ln!(
        out,
        "    connect_timeout: {}",
        format_envoy_seconds(c.connect_timeout_ms)
    );
    // dynamic_forward_proxy cluster: the no-endpoint shape Envoy
    // resolves DNS on demand per upstream request. Non-empty
    // endpoint list → STATIC cluster with a load_assignment.
    //
    // Envoy's cluster proto puts `type` (`DiscoveryType` enum:
    // STATIC / STRICT_DNS / LOGICAL_DNS / EDS / ORIGINAL_DST) and
    // `cluster_type` (`CustomClusterType` message for extension
    // clusters like `envoy.clusters.dynamic_forward_proxy`) in a
    // `oneof discovery_type` — exactly one of them must be set
    // per cluster. Setting both is a protobuf-level oneof
    // violation that newer Envoy versions reject at parse time
    // (`envoy --mode validate` fails with "more than one value
    // set in oneof"); older versions silently kept the last-set
    // field, with `cluster_type` always winning. The canonical
    // Envoy upstream example for dynamic_forward_proxy
    // (https://www.envoyproxy.io/docs/envoy/latest/configuration/
    // http/http_filters/dynamic_forward_proxy_filter) sets only
    // `cluster_type`, never `type`, for exactly this reason.
    //
    // `lb_policy: CLUSTER_PROVIDED` stays — the LB-policy enum is
    // a separate field from `discovery_type`, and dynamic_forward_proxy
    // is documented to require `CLUSTER_PROVIDED` (the cluster
    // extension manages its own host set, so Envoy's normal
    // round-robin / least-request LBs would race with the
    // DNS-cache shape).
    if c.endpoints.is_empty() {
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

/// Split a `host:port` endpoint string into its parts.
///
/// Two shapes are accepted:
///
/// 1. **IPv4 / hostname.** `10.0.0.5:8080`, `example.com:443`.
///    A single `rsplit_once(':')` is unambiguous — there is
///    exactly one colon in the input.
/// 2. **IPv6 bracketed.** `[::1]:8080`, `[2001:db8::1]:443`.
///    RFC 3986 §3.2.2 mandates square brackets around the IPv6
///    address in `host:port` notation so the colon-rich IPv6
///    literal doesn't ambiguate with the port separator. The
///    host slice returned to the caller is the address inside
///    the brackets — bare `::1`, not `[::1]` — because Envoy's
///    `socket_address.address` field expects the unbracketed
///    form (the brackets are URI-level syntax, not part of the
///    address itself). Rendering `[::1]` would either be
///    rejected by `envoy --mode validate` or, worse, accepted
///    on a lenient Envoy build and silently treated as a
///    literal hostname string — neither of which connects to
///    the intended IPv6 upstream.
///
/// Without the bracket-aware split, a naive `rsplit_once(':')`
/// on `[::1]:8080` yields `host = "[::1]"`, `port = "8080"`,
/// and the renderer emits `address: "[::1]"` into the Envoy
/// YAML. The current production wiring doesn't hit this path
/// (ext-authz uses a unix socket, the forward-proxy cluster is
/// endpointless `dynamic_forward_proxy`), but an operator who
/// adds a custom IPv6 upstream cluster via the future
/// `extra_yaml` hook would silently produce a non-functional
/// config. Handle the bracket shape correctly at the renderer
/// layer so the failure mode is "port number rejected as not
/// `u16`" (loud, surfaced at install-time) rather than
/// "silently emits unreachable upstream" (quiet, surfaced only
/// when the cluster is exercised in production).
fn parse_host_port(ep: &str) -> Result<(&str, u16), SwgError> {
    let (host, port) = if let Some(rest) = ep.strip_prefix('[') {
        // RFC 3986 §3.2.2 bracketed IPv6 form: `[<addr>]:<port>`.
        // Find the matching `]` and require `:` immediately
        // after — anything else (no `]`, no `:` after `]`, or
        // characters between `]` and `:`) is a malformed
        // endpoint and surfaces a `Config` error at install
        // time rather than rendering an invalid YAML the
        // operator only discovers at process-start.
        let close = rest
            .find(']')
            .ok_or_else(|| SwgError::Config(format!("endpoint missing closing bracket: {ep}")))?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after.strip_prefix(':').ok_or_else(|| {
            SwgError::Config(format!("endpoint missing port after bracketed host: {ep}"))
        })?;
        (host, port)
    } else {
        ep.rsplit_once(':')
            .ok_or_else(|| SwgError::Config(format!("endpoint missing port: {ep}")))?
    };
    let port: u16 = port
        .parse()
        .map_err(|e| SwgError::Config(format!("endpoint port not u16 ({ep}): {e}")))?;
    Ok((host, port))
}

/// Render a millisecond integer as the seconds-string shape
/// Envoy's protobuf `Duration` parser accepts in YAML (e.g.
/// `0.250s`, `1.500s`, `5s`, `30s`).
///
/// Envoy 1.30+ parses durations from the typed config layer via
/// `google.protobuf.Duration` (`<seconds>[.<fraction>]s`). We
/// emit the canonical lowest-precision form so the YAML stays
/// stable (no trailing zeroes, no scientific notation) across
/// renders. Sub-second values are emitted with millisecond
/// precision (`0.250s`); whole-second values drop the
/// fractional part (`5s`). Pinned by
/// `format_envoy_seconds_renders_canonical_form`.
fn format_envoy_seconds(ms: u32) -> String {
    let secs = ms / 1_000;
    let frac_ms = ms % 1_000;
    if frac_ms == 0 {
        format!("{secs}s")
    } else {
        // Three-digit zero-padded fraction so 50 ms renders as
        // `0.050s` not `0.50s` (which protobuf parses as 500 ms,
        // a 10x discrepancy that would silently widen the timeout
        // by an order of magnitude).
        format!("{secs}.{frac_ms:03}s")
    }
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
    fn admin_port_default_is_9901_and_renders_into_admin_block() {
        // The renderer used to hardcode `port_value: 9901` in
        // the admin block, which silently disagreed with
        // `ShellEnvoy::admin_port` whenever an operator overrode
        // the supervisor's healthcheck port. The fix promotes
        // the admin port to a struct field so the renderer
        // emits whatever the operator wired in. This test pins
        // the default value matches `DEFAULT_ADMIN_PORT` and the
        // renderer emits that exact value inside the admin
        // socket_address block (not just somewhere in the file —
        // a listener that happens to bind 9901 would otherwise
        // give a false positive).
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        assert_eq!(cfg.admin_port, DEFAULT_ADMIN_PORT);
        let s = render_envoy_yaml(&cfg).unwrap();
        let admin_block = "admin:\n  address:\n    socket_address:\n      address: 127.0.0.1\n      port_value: 9901\n";
        assert!(
            s.contains(admin_block),
            "default admin port must render as 9901 inside the admin block; got:\n{s}",
        );
    }

    #[test]
    fn admin_port_override_renders_into_admin_block() {
        // Regression test for the bot's renderer/supervisor
        // divergence finding. The pre-fix renderer hardcoded
        // 9901 in the admin block, so an operator who wired
        // `with_admin_port(15001)` on the supervisor would
        // healthcheck a port Envoy never bound. The fix threads
        // the configured port through the renderer; this test
        // pins that the override actually lands in the admin
        // block, not just that the field is settable.
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock")
            .with_admin_port(15_001);
        let s = render_envoy_yaml(&cfg).unwrap();
        let admin_block = "admin:\n  address:\n    socket_address:\n      address: 127.0.0.1\n      port_value: 15001\n";
        assert!(
            s.contains(admin_block),
            "overridden admin port must render in the admin block; got:\n{s}",
        );
        // And the default 9901 must NOT appear there — a future
        // refactor that drops the field reference would still
        // pass the override assertion if it emitted both ports.
        assert!(
            !s.contains("      port_value: 9901\n"),
            "default admin port must not leak into the rendered output \
             when the operator has overridden it; got:\n{s}",
        );
    }

    #[test]
    fn admin_port_change_flips_render_digest() {
        // The supervisor's hot-swap dedup keys on the rendered
        // config's SHA-256. If the renderer ignored
        // `admin_port`, two configs differing only in admin port
        // would hash equal and the supervisor would skip the
        // restart needed to actually move the admin endpoint.
        // This test pins that the admin_port participates in the
        // digest.
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let d0 = digest_envoy_yaml(&render_envoy_yaml(&cfg).unwrap());
        cfg.admin_port = 15_001;
        let d1 = digest_envoy_yaml(&render_envoy_yaml(&cfg).unwrap());
        assert_ne!(d0, d1, "admin_port must participate in the rendered digest");
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
            admin_port: DEFAULT_ADMIN_PORT,
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
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(s.contains("address: \"10.0.0.5\""));
        assert!(s.contains("port_value: 8080"));
        // connect_timeout: 1500ms → 1.500s.
        // `format_envoy_seconds` canonical form: 1500 ms has a
        // fractional component, so the dotted shape stays.
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
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(s.contains("dynamic_forward_proxy_cache_config"));
        // `format_envoy_seconds` canonical form: 5_000 ms is
        // exactly 5 seconds so the fractional part is elided. The
        // historical inline formatter emitted `5.000s`, which is
        // semantically identical to Envoy but split the
        // digest-dedup hash space against the ext_authz timeout
        // slot's `5s` rendering for the same duration. Routing
        // both slots through `format_envoy_seconds` collapses
        // them to one canonical form.
        assert!(s.contains("connect_timeout: 5s"), "got\n{s}");
    }

    #[test]
    fn dynamic_forward_proxy_omits_type_field_to_satisfy_oneof_invariant() {
        // Envoy's `Cluster` proto puts `type` (`DiscoveryType` enum)
        // and `cluster_type` (`CustomClusterType` message) in a
        // `oneof discovery_type` — setting both is a protobuf-level
        // violation that newer Envoy versions reject at parse time
        // with "more than one value set in oneof". The endpointless
        // (dynamic_forward_proxy) render path therefore emits ONLY
        // `cluster_type`, never `type`. Pin that invariant so a
        // future regression that adds `type: STRICT_DNS` back fails
        // here loudly rather than at a downstream `envoy --mode
        // validate` cycle.
        //
        // `lb_policy: CLUSTER_PROVIDED` stays (separate field from
        // discovery_type, and dynamic_forward_proxy is documented
        // to require it). The STATIC path keeps emitting `type:
        // STATIC` — that's the same oneof field, just the
        // built-in enum side, and is correct.
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "fwd".into(),
                endpoints: Vec::new(),
                connect_timeout_ms: 5_000,
            }],
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(
            !s.contains("type: STRICT_DNS"),
            "endpointless cluster must NOT emit `type:` alongside `cluster_type:` \
             (oneof discovery_type violation); got\n{s}"
        );
        assert!(
            !s.contains("type: LOGICAL_DNS"),
            "endpointless cluster must NOT emit `type:` alongside `cluster_type:` \
             (oneof discovery_type violation); got\n{s}"
        );
        assert!(
            s.contains("lb_policy: CLUSTER_PROVIDED"),
            "endpointless cluster must keep `lb_policy: CLUSTER_PROVIDED` \
             (required by dynamic_forward_proxy); got\n{s}"
        );
        assert!(
            s.contains("cluster_type:"),
            "endpointless cluster must emit `cluster_type:`; got\n{s}"
        );
        assert!(
            s.contains("envoy.clusters.dynamic_forward_proxy"),
            "endpointless cluster must name the dynamic_forward_proxy extension; got\n{s}"
        );
    }

    #[test]
    fn static_cluster_still_emits_type_static_on_oneof_field() {
        // Mirror invariant on the STATIC side of the oneof: when
        // `endpoints` is non-empty we go through the
        // `load_assignment` shape and `type: STATIC` IS the
        // discovery_type setting. Pin that the STATIC path keeps
        // emitting exactly one oneof field (`type`, not
        // `cluster_type`) so a future refactor that incorrectly
        // unifies the two paths cannot silently drop the
        // discovery type.
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "ext_authz".into(),
                endpoints: vec!["127.0.0.1:9001".into()],
                connect_timeout_ms: 1_000,
            }],
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(
            s.contains("type: STATIC"),
            "STATIC cluster must emit `type: STATIC`; got\n{s}"
        );
        assert!(
            !s.contains("cluster_type:"),
            "STATIC cluster must NOT emit `cluster_type:` (oneof discovery_type \
             violation); got\n{s}"
        );
        assert!(
            !s.contains("dynamic_forward_proxy"),
            "STATIC cluster must not leak dynamic_forward_proxy strings; got\n{s}"
        );
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
    fn parse_host_port_handles_bracketed_ipv6_loopback() {
        // RFC 3986 §3.2.2 bracketed IPv6 form. The host slice
        // must be the address inside the brackets — Envoy's
        // socket_address.address field expects the unbracketed
        // form, so emitting `[::1]` would either be rejected at
        // validate-time or silently treated as a literal
        // hostname string.
        let (h, p) = parse_host_port("[::1]:8080").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 8080);
    }

    #[test]
    fn parse_host_port_handles_bracketed_ipv6_full() {
        let (h, p) = parse_host_port("[2001:db8::1]:443").unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, 443);
    }

    #[test]
    fn parse_host_port_rejects_bracketed_without_close() {
        let err = parse_host_port("[::1:8080").expect_err("must reject");
        match err {
            SwgError::Config(m) => assert!(m.contains("missing closing bracket"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn parse_host_port_rejects_bracketed_without_port_separator() {
        // `[::1]` with no `:<port>` after the close-bracket
        // must surface as a Config error at install time, not
        // render an invalid YAML the operator only discovers
        // when Envoy fails to start.
        let err = parse_host_port("[::1]").expect_err("must reject");
        match err {
            SwgError::Config(m) => assert!(m.contains("missing port after bracketed host"), "{m}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn render_endpoint_emits_unbracketed_ipv6_for_envoy_socket_address() {
        // End-to-end check: a bracketed IPv6 cluster endpoint
        // must reach the rendered YAML as the unbracketed form
        // so Envoy's socket_address.address field accepts it.
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "ipv6_upstream".into(),
                endpoints: vec!["[2001:db8::1]:443".into()],
                connect_timeout_ms: 1_000,
            }],
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).expect("render must succeed");
        // Address line carries the bare IPv6 literal, NOT the
        // bracketed URI form.
        assert!(
            s.contains("address: \"2001:db8::1\""),
            "expected unbracketed IPv6 address in rendered YAML, got:\n{s}"
        );
        // Defensive: no bracketed form anywhere — a regression
        // that re-introduces the naive rsplit would render
        // `address: "[2001:db8::1]"`, which this assertion
        // catches.
        assert!(
            !s.contains("address: \"[2001"),
            "rendered YAML must not contain bracketed IPv6 address, got:\n{s}"
        );
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

    #[test]
    fn format_envoy_seconds_renders_canonical_form() {
        // Sub-second values keep three-digit millisecond
        // precision so 50 ms doesn't render as `0.50s` (which
        // protobuf's Duration parser would read as 500 ms — a
        // silent 10x widening of the timeout).
        assert_eq!(format_envoy_seconds(250), "0.250s");
        assert_eq!(format_envoy_seconds(50), "0.050s");
        assert_eq!(format_envoy_seconds(1), "0.001s");
        // Whole-second values drop the fractional part so the
        // wire shape stays stable across renders.
        assert_eq!(format_envoy_seconds(1_000), "1s");
        assert_eq!(format_envoy_seconds(5_000), "5s");
        assert_eq!(format_envoy_seconds(30_000), "30s");
        // Mixed (whole + fractional) keep the fractional part.
        assert_eq!(format_envoy_seconds(1_500), "1.500s");
        assert_eq!(format_envoy_seconds(2_750), "2.750s");
        // Zero is a degenerate "no timeout" value — Envoy
        // interprets `0s` as "disabled". We emit the canonical
        // form so an operator who wants this gets the wire shape
        // their intent maps to.
        assert_eq!(format_envoy_seconds(0), "0s");
    }

    #[test]
    fn default_ext_authz_timeout_renders_as_250ms() {
        // The historical hardcoded `timeout: 0.250s` was the
        // wire-format default for the in-process providers
        // sng-swg ships at launch. The fix promotes the timeout
        // to a per-listener field — this test pins that the
        // default rendered value did not regress when the field
        // became dynamic. An operator using only
        // `minimal_forward_proxy()` (no override) must see
        // exactly the same Envoy YAML the historical renderer
        // produced.
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        assert_eq!(
            cfg.listeners[0].ext_authz_timeout_ms,
            DEFAULT_EXT_AUTHZ_TIMEOUT_MS
        );
        assert_eq!(DEFAULT_EXT_AUTHZ_TIMEOUT_MS, 250);
        let s = render_envoy_yaml(&cfg).unwrap();
        // Pin the rendered substring so a future field rename
        // (`ext_authz_timeout_ms` -> ?) that forgets to update
        // the renderer trips this test.
        assert!(
            s.contains("                  timeout: 0.250s\n"),
            "default ext-authz timeout must render as 0.250s; got:\n{s}",
        );
    }

    #[test]
    fn ext_authz_timeout_override_renders_dynamically() {
        // Regression test for the Devin Review finding: the
        // historical renderer hardcoded `timeout: 0.250s`,
        // which was generous for the in-process providers but
        // would have caused Envoy to fail-closed deny every
        // request once a remote provider (Cisco Talos, custom
        // HTTPS feed, managed verdict service) was wired in and
        // its 99th-percentile latency overran the 250 ms
        // window. The fix promotes the timeout to a per-listener
        // field; this test pins that the override actually
        // lands in the rendered Envoy YAML at the ext_authz
        // HTTP service block, not just that the field is
        // settable.
        //
        // Multi-second override (remote provider envelope):
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg.listeners[0].ext_authz_timeout_ms = 5_000;
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(
            s.contains("                  timeout: 5s\n"),
            "5s override must render at the ext_authz timeout slot; got:\n{s}",
        );
        // The default value must NOT appear anywhere in the
        // rendered YAML for the override path — a future
        // refactor that drops the field reference would still
        // pass the override assertion if it emitted both
        // timeouts.
        assert!(
            !s.contains("                  timeout: 0.250s\n"),
            "default 250ms timeout must not leak into the rendered output \
             when the operator has overridden it; got:\n{s}",
        );

        // Sub-second override (slightly slower in-process
        // provider envelope):
        cfg.listeners[0].ext_authz_timeout_ms = 750;
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(
            s.contains("                  timeout: 0.750s\n"),
            "750ms override must render at the ext_authz timeout slot; got:\n{s}",
        );

        // Multi-listener override — each listener carries its
        // own timeout so a mixed in-process / remote-provider
        // deployment can size each one independently.
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg.listeners.push(ListenerConfig {
            name: "swg_forward_remote".into(),
            address: "0.0.0.0".into(),
            port: 9443,
            ext_authz_cluster: "ext_authz_remote".into(),
            forward_proxy_cluster: "dynamic_forward_proxy".into(),
            tls_bypass_sni_suffixes: Vec::new(),
            ext_authz_timeout_ms: 3_000,
        });
        let s = render_envoy_yaml(&cfg).unwrap();
        assert!(
            s.contains("                  timeout: 0.250s\n"),
            "first listener's 250ms timeout must still render; got:\n{s}",
        );
        assert!(
            s.contains("                  timeout: 3s\n"),
            "second listener's 3s timeout must render; got:\n{s}",
        );
    }

    #[test]
    fn connect_timeout_renders_via_format_envoy_seconds_for_parity() {
        // Both protobuf-Duration slots in the rendered YAML must
        // route through `format_envoy_seconds` so a whole-second
        // value emits the same canonical form regardless of which
        // slot it lands in. The historical inline formatter
        // hardcoded `{secs}.{millis:03}s`, which made
        // `connect_timeout: 5_000` render as `5.000s` while the
        // ext_authz `timeout: 5_000` rendered as `5s` — two wire
        // shapes for the same duration, splitting the
        // digest-dedup hash space and giving two future schema
        // changes opposite-direction drift surfaces. The fix
        // unifies both paths on `format_envoy_seconds`; pin the
        // unified behaviour so a future refactor that reintroduces
        // an inline `{millis:03}` formatter trips this test.
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![
                ClusterConfig {
                    name: "five_sec".into(),
                    endpoints: vec!["10.0.0.5:8080".into()],
                    connect_timeout_ms: 5_000,
                },
                ClusterConfig {
                    name: "one_sec".into(),
                    endpoints: vec!["10.0.0.6:8080".into()],
                    connect_timeout_ms: 1_000,
                },
                ClusterConfig {
                    name: "frac".into(),
                    endpoints: vec!["10.0.0.7:8080".into()],
                    connect_timeout_ms: 750,
                },
            ],
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).unwrap();
        // Whole seconds: bare integer form, not `5.000s`.
        assert!(
            s.contains("    connect_timeout: 5s\n"),
            "5000ms must render as `5s` to match ext_authz parity; got:\n{s}",
        );
        assert!(
            s.contains("    connect_timeout: 1s\n"),
            "1000ms must render as `1s` to match ext_authz parity; got:\n{s}",
        );
        // Sub-second: three-digit zero-padded fraction so 750 ms
        // doesn't render as `0.75s` (which protobuf parses as
        // 750 ms — same as we want — but the canonical form is
        // explicit about ms precision).
        assert!(
            s.contains("    connect_timeout: 0.750s\n"),
            "750ms must render as `0.750s`; got:\n{s}",
        );
        // The historical `5.000s` form must NOT appear anywhere
        // in the output — a regression that flipped one slot back
        // to the inline formatter would still pass the `5s` check
        // by leaking the older form into the other slots.
        assert!(
            !s.contains("connect_timeout: 5.000s"),
            "historical inline `5.000s` form must not appear; got:\n{s}",
        );
    }

    #[test]
    fn render_rejects_zero_ext_authz_timeout_as_fail_closed_guard() {
        // Envoy's protobuf `Duration` parser reads `0s` as
        // "disabled" — the ext_authz hop would have no timeout,
        // so a hung verdict provider would stall every in-flight
        // request indefinitely rather than tripping the
        // fail-closed deny that sng-swg sits in front of Envoy to
        // enforce. Reject this at render time so a typo in a
        // persisted bundle (`ext_authz_timeout_ms: 0`), a
        // default-initialised struct literal in test code, or a
        // careless field elision surfaces as a loud Config error
        // at install rather than silently widening the timeout
        // to unbounded.
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg.listeners[0].ext_authz_timeout_ms = 0;
        let err = render_envoy_yaml(&cfg).expect_err("zero timeout must reject");
        match err {
            SwgError::Config(msg) => {
                assert!(
                    msg.contains("ext_authz_timeout_ms = 0"),
                    "error must name the offending field; got: {msg}",
                );
                assert!(
                    msg.contains("disabled"),
                    "error must explain the Envoy parse semantic; got: {msg}",
                );
                assert!(
                    msg.contains("fail-closed"),
                    "error must connect the rejection to the safety invariant; got: {msg}",
                );
            }
            other => panic!("expected SwgError::Config, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_zero_ext_authz_timeout_on_any_listener_not_just_first() {
        // Multi-listener deployments split per-tenant or
        // per-cluster traffic across separate listeners; the
        // fail-closed-disable check must walk every listener so a
        // second listener with a zero timeout doesn't slip
        // through because the first listener's value is sane.
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg.listeners.push(ListenerConfig {
            name: "swg_forward_secondary".into(),
            address: "0.0.0.0".into(),
            port: 9443,
            ext_authz_cluster: "ext_authz".into(),
            forward_proxy_cluster: "dynamic_forward_proxy".into(),
            tls_bypass_sni_suffixes: Vec::new(),
            ext_authz_timeout_ms: 0,
        });
        let err = render_envoy_yaml(&cfg).expect_err("zero on any listener must reject");
        match err {
            SwgError::Config(msg) => {
                // Name the offending listener so an operator with
                // a many-listener bundle can find the typo.
                assert!(
                    msg.contains("swg_forward_secondary"),
                    "error must name the offending listener; got: {msg}",
                );
            }
            other => panic!("expected SwgError::Config, got {other:?}"),
        }
    }

    #[test]
    fn listener_config_deserializes_without_ext_authz_timeout_field() {
        // Forward compatibility: bundles serialised before the
        // `ext_authz_timeout_ms` field was added must still
        // deserialise, with the field falling back to
        // `DEFAULT_EXT_AUTHZ_TIMEOUT_MS`. Without
        // `#[serde(default)]` on the field, an older bundle
        // would fail with `missing field 'ext_authz_timeout_ms'`
        // and the control-plane round-trip path (cache reload,
        // replay log, on-disk bundle store) would break across
        // the version boundary.
        let json = r#"{
            "name": "legacy",
            "address": "0.0.0.0",
            "port": 8443,
            "ext_authz_cluster": "ext_authz",
            "forward_proxy_cluster": "dynamic_forward_proxy",
            "tls_bypass_sni_suffixes": []
        }"#;
        let l: ListenerConfig =
            serde_json::from_str(json).expect("legacy JSON without ext_authz_timeout_ms must load");
        assert_eq!(
            l.ext_authz_timeout_ms, DEFAULT_EXT_AUTHZ_TIMEOUT_MS,
            "missing field must fall back to the documented default",
        );
        // And the loaded shape must render successfully — i.e.
        // the default value doesn't trip the fail-closed-disable
        // guard.
        let cfg = EnvoyConfig {
            listeners: vec![l],
            clusters: vec![ClusterConfig {
                name: "ext_authz".into(),
                endpoints: vec!["unix:///x".into()],
                connect_timeout_ms: 1_000,
            }],
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let s = render_envoy_yaml(&cfg).expect("legacy bundle must render");
        assert!(
            s.contains("                  timeout: 0.250s\n"),
            "legacy bundle must inherit the historical 250ms timeout; got:\n{s}",
        );
    }

    #[test]
    fn render_rejects_zero_connect_timeout_as_symmetric_guard() {
        // Symmetric foot-gun to `ext_authz_timeout_ms = 0`.
        // Envoy's protobuf `Duration` parser reads `0s` on a
        // cluster `connect_timeout` as "no timeout" on the
        // upstream TCP connect. For a STATIC cluster a zero
        // connect timeout means Envoy waits indefinitely for the
        // upstream socket — a black-holed upstream pins the
        // worker thread on connect with no operator-visible
        // signal. The endpointless `dynamic_forward_proxy`
        // cluster gets DNS-resolved per request, but Envoy still
        // applies `connect_timeout` on the resolved socket
        // connect, so the same hang applies. Reject at render
        // time, naming the offending cluster.
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        // The minimal forward-proxy config puts the ext_authz
        // cluster at index 0 and dynamic_forward_proxy at index 1
        // — zero either and the guard must trip.
        cfg.clusters[0].connect_timeout_ms = 0;
        let err = render_envoy_yaml(&cfg).expect_err("zero connect timeout must reject");
        match err {
            SwgError::Config(msg) => {
                assert!(
                    msg.contains("connect_timeout_ms = 0"),
                    "error must name the offending field; got: {msg}",
                );
                assert!(
                    msg.contains("no timeout"),
                    "error must explain the Envoy parse semantic; got: {msg}",
                );
                assert!(
                    msg.contains("ext_authz"),
                    "error must name the offending cluster; got: {msg}",
                );
            }
            other => panic!("expected SwgError::Config, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_zero_connect_timeout_on_any_cluster_not_just_first() {
        // Walk-all-clusters parity with the listener-side guard:
        // a second cluster with a zero connect timeout must not
        // slip through because the first cluster is sane.
        let mut cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        // dynamic_forward_proxy is index 1 in the minimal config;
        // zero it out so the first cluster passes the check and
        // the second one trips it.
        cfg.clusters[1].connect_timeout_ms = 0;
        let err = render_envoy_yaml(&cfg).expect_err("zero on any cluster must reject");
        match err {
            SwgError::Config(msg) => {
                // The offending cluster name must be in the
                // error so an operator with a many-cluster
                // bundle can find the typo.
                assert!(
                    msg.contains("dynamic_forward_proxy"),
                    "error must name the second cluster as the offender; got: {msg}",
                );
            }
            other => panic!("expected SwgError::Config, got {other:?}"),
        }
    }

    #[test]
    fn render_rejects_zero_connect_timeout_on_endpointless_cluster_too() {
        // `dynamic_forward_proxy` is the canonical endpointless
        // cluster shape (DNS resolved per request). Envoy still
        // honours `connect_timeout` on the resolved upstream
        // socket connect, so the foot-gun is identical to the
        // STATIC cluster case. The carve-out a casual reader
        // might assume ("zero is fine on endpointless clusters
        // because Envoy resolves DNS itself") does NOT apply.
        let cfg = EnvoyConfig {
            listeners: Vec::new(),
            clusters: vec![ClusterConfig {
                name: "dynamic_forward_proxy".into(),
                endpoints: Vec::new(),
                connect_timeout_ms: 0,
            }],
            admin_port: DEFAULT_ADMIN_PORT,
        };
        let err =
            render_envoy_yaml(&cfg).expect_err("zero on endpointless cluster must also reject");
        match err {
            SwgError::Config(msg) => {
                assert!(
                    msg.contains("connect_timeout_ms = 0"),
                    "error must name the offending field; got: {msg}",
                );
                assert!(
                    msg.contains("dynamic_forward_proxy"),
                    "error must name the offending cluster; got: {msg}",
                );
            }
            other => panic!("expected SwgError::Config, got {other:?}"),
        }
    }
}
