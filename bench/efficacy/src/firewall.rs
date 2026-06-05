//! Firewall (NGFW) efficacy: drive the *real* `sng_fw::FirewallEngine`
//! decision path over a known-bad + known-good flow corpus, and verify
//! that SNG's `RuleCompiler` emits a kernel-valid nftables ruleset.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use std::sync::Arc;

use ipnet::IpNet;
use sng_fw::{
    CompiledRuleSet, EvaluationContext, FirewallEngine, FirewallRule, FlowDirection, FlowKey,
    MockNftables, NatTable, NftablesScript, PortRange, Protocol, RuleAction, RuleCompiler,
    RuleMatch, ZoneTable,
};
use sng_policy_eval::bundle::LoadedBundle;

use crate::report::{Case, FunctionReport, Kind, Targets};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn deny_port(id: &str, port: u16) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        matches: RuleMatch {
            dst_ports: vec![PortRange::single(port)],
            protocol: Protocol::Tcp,
            ..RuleMatch::default()
        },
        action: RuleAction::Deny,
        from_zones: vec![],
        to_zones: vec![],
        description: format!("deny tcp/{port}"),
    }
}

fn deny_cidr(id: &str, cidr: &str) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        matches: RuleMatch {
            dst_cidrs: vec![cidr.parse::<IpNet>().expect("cidr")],
            ..RuleMatch::default()
        },
        action: RuleAction::Deny,
        from_zones: vec![],
        to_zones: vec![],
        description: format!("deny dst {cidr}"),
    }
}

fn allow_port(id: &str, port: u16) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        matches: RuleMatch {
            dst_ports: vec![PortRange::single(port)],
            protocol: Protocol::Tcp,
            ..RuleMatch::default()
        },
        action: RuleAction::Allow,
        from_zones: vec![],
        to_zones: vec![],
        description: format!("allow tcp/{port}"),
    }
}

fn allow_udp_port(id: &str, port: u16) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        matches: RuleMatch {
            dst_ports: vec![PortRange::single(port)],
            protocol: Protocol::Udp,
            ..RuleMatch::default()
        },
        action: RuleAction::Allow,
        from_zones: vec![],
        to_zones: vec![],
        description: format!("allow udp/{port}"),
    }
}

/// Realistic edge policy: explicit allowlist for web/DNS, explicit
/// deny for legacy/admin services + a known-bad destination block,
/// default-deny baseline (fail-closed).
fn policy_ruleset() -> CompiledRuleSet {
    CompiledRuleSet {
        rules: vec![
            // Block legacy / lateral-movement services first.
            deny_port("deny-telnet", 23),
            deny_port("deny-smb", 445),
            deny_port("deny-rdp", 3389),
            deny_port("deny-exfil", 9999),
            // Block a known-bad destination network (threat-intel feed).
            deny_cidr("deny-badnet", "203.0.113.0/24"),
            // Allow sanctioned egress.
            allow_port("allow-https", 443),
            allow_port("allow-http", 80),
            // DNS over both transports: UDP is the common path, TCP for
            // zone transfers / large (>512B) responses. Protocol is matched
            // exactly (only `Protocol::Any` wildcards), so each transport
            // needs its own allow rule.
            allow_udp_port("allow-dns-udp", 53),
            allow_port("allow-dns-tcp", 53),
        ],
        zones: ZoneTable::new(),
        nat: NatTable::new(),
        default_action: RuleAction::Deny, // fail-closed baseline
        source_graph_id: "efficacy-fw".into(),
        source_graph_version: 1,
        script: NftablesScript::new(b"add table inet sng_filter\n".to_vec()),
    }
}

struct FlowCase {
    desc: &'static str,
    bad: bool,
    src: IpAddr,
    dst: IpAddr,
    dport: u16,
    proto: Protocol,
}

fn corpus() -> Vec<FlowCase> {
    vec![
        // --- known-bad: MUST be denied ---
        FlowCase {
            desc: "telnet to internal host (legacy, lateral movement)",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(10, 0, 0, 9),
            dport: 23,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "SMB/445 east-west (ransomware spread vector)",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(10, 0, 0, 20),
            dport: 445,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "RDP/3389 exposed to workstation",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(10, 0, 0, 30),
            dport: 3389,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "exfil to high port 9999",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(198, 51, 100, 7),
            dport: 9999,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "egress to known-bad net 203.0.113.0/24",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(203, 0, 113, 5),
            dport: 443,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "unsanctioned tcp port 31337 (default-deny)",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(93, 184, 216, 34),
            dport: 31337,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "unsanctioned udp port 12345 (default-deny, UDP path)",
            bad: true,
            src: v4(10, 0, 0, 5),
            dst: v4(93, 184, 216, 34),
            dport: 12345,
            proto: Protocol::Udp,
        },
        // --- known-good: MUST be allowed ---
        FlowCase {
            desc: "HTTPS/443 to public web",
            bad: false,
            src: v4(10, 0, 0, 5),
            dst: v4(93, 184, 216, 34),
            dport: 443,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "HTTP/80 to public web",
            bad: false,
            src: v4(10, 0, 0, 5),
            dst: v4(93, 184, 216, 34),
            dport: 80,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "DNS/53 (UDP) to resolver",
            bad: false,
            src: v4(10, 0, 0, 5),
            dst: v4(1, 1, 1, 1),
            dport: 53,
            proto: Protocol::Udp,
        },
        FlowCase {
            desc: "DNS/53 (TCP) zone transfer to resolver",
            bad: false,
            src: v4(10, 0, 0, 5),
            dst: v4(1, 1, 1, 1),
            dport: 53,
            proto: Protocol::Tcp,
        },
        FlowCase {
            desc: "HTTPS/443 to SaaS app",
            bad: false,
            src: v4(10, 0, 0, 6),
            dst: v4(140, 82, 112, 3),
            dport: 443,
            proto: Protocol::Tcp,
        },
    ]
}

/// Default-deny bundle through the production decode path, used to
/// render an SNG nftables script and kernel-validate it.
fn fail_closed_bundle() -> LoadedBundle {
    #[derive(serde::Serialize)]
    struct Wire<'a> {
        #[serde(rename = "v")]
        v: u8,
        #[serde(rename = "t")]
        t: &'a str,
        #[serde(rename = "g")]
        g: &'a str,
        #[serde(rename = "gv")]
        gv: i64,
        #[serde(rename = "c")]
        c: &'a str,
        #[serde(rename = "d")]
        d: &'a str,
        #[serde(rename = "r", with = "serde_bytes")]
        r: &'a [u8],
        #[serde(rename = "ts")]
        ts: &'a str,
    }
    let wire = Wire {
        v: 1,
        t: "edge",
        g: "efficacy-fw",
        gv: 1,
        c: "demo",
        d: "deny",
        r: b"[]",
        ts: "2026-06-05T00:00:00Z",
    };
    let body = rmp_serde::to_vec_named(&wire).expect("encode bundle");
    LoadedBundle::from_body(&body, sng_core::policy::BundleTarget::Edge).expect("decode bundle")
}

/// Render an SNG ruleset and ask the kernel's nft parser to validate
/// it (`nft -c`, check-only — never commits, so VM connectivity is
/// untouched). Returns a human note describing the result.
async fn kernel_validation_note() -> String {
    let bundle = fail_closed_bundle();
    let compiled = match RuleCompiler::new().compile(&bundle, ZoneTable::new(), NatTable::new()) {
        Ok(c) => c,
        Err(e) => return format!("RuleCompiler failed to render nftables: {e}"),
    };
    let script = match compiled.script.as_str() {
        Some(s) => s.to_string(),
        None => return "rendered nftables script was not valid UTF-8".into(),
    };
    let mut child = match tokio::process::Command::new("sudo")
        .args(["-n", "nft", "-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return format!(
                "nft not runnable ({e}); rendered script ({} bytes) not kernel-validated",
                script.len()
            )
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(script.as_bytes()).await;
        let _ = stdin.shutdown().await;
    }
    match child.wait_with_output().await {
        Ok(out) if out.status.success() => {
            "SNG RuleCompiler emitted a default-deny nftables ruleset; the Linux \
             kernel nft parser accepts it (`nft -c -f -` exit 0) — the rendered \
             enforcement artifact is syntactically and semantically valid."
                .into()
        }
        Ok(out) => format!(
            "kernel rejected SNG-rendered ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("nft check failed to run: {e}"),
    }
}

pub async fn run() -> FunctionReport {
    let engine = FirewallEngine::new(Arc::new(MockNftables::new()));

    // Fail-closed sanity: with no ruleset loaded, the engine denies.
    let pre = engine.evaluate(&EvaluationContext {
        flow: FlowKey::new(v4(10, 0, 0, 1), v4(8, 8, 8, 8), 33333, 443, Protocol::Tcp),
        direction: FlowDirection::Original,
        subject_value: None,
    });
    let fail_closed_ok = pre.action == RuleAction::Deny;

    engine
        .install(policy_ruleset())
        .await
        .expect("install firewall ruleset");

    let mut cases = Vec::new();
    for f in corpus() {
        let verdict = engine.evaluate(&EvaluationContext {
            flow: FlowKey::new(f.src, f.dst, 33333, f.dport, f.proto),
            direction: FlowDirection::Original,
            subject_value: None,
        });
        let denied = verdict.action == RuleAction::Deny;
        // bad => expect deny; good => expect allow.
        let correct = if f.bad { denied } else { !denied };
        cases.push(Case {
            description: f.desc.into(),
            bad: f.bad,
            expected: if f.bad { "deny" } else { "allow" }.into(),
            actual: if denied { "deny" } else { "allow" }.into(),
            correct,
        });
    }

    let kval = kernel_validation_note().await;
    let notes = format!(
        "Fail-closed default (no ruleset loaded -> Deny): {}. {}",
        if fail_closed_ok {
            "verified"
        } else {
            "NOT verified"
        },
        kval
    );

    FunctionReport::from_cases(
        "firewall",
        "sng-fw",
        Kind::Enforcement,
        Targets::default(),
        cases,
        Some(notes),
    )
}
