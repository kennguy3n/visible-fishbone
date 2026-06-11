//! Kernel nftables conformance: prove the ruleset SNG's `RuleCompiler`
//! renders enforces the *same* verdict in the Linux kernel that the
//! in-memory [`sng_fw::FirewallEngine`] returns.
//!
//! Where [`crate::firewall`] checks the rendered script is kernel-*valid*
//! (`nft -c`, parse-only), this driver checks it is kernel-*correct*: it
//! installs the SNG-rendered script in a throwaway network namespace,
//! forwards a crafted probe packet per corpus flow through a veth pair,
//! and reads back the kernel's verdict. Any divergence from the userspace
//! engine is a real renderer bug, not a test artifact.
//!
//! Topology (all in per-run namespaces, torn down on every exit path):
//!
//! ```text
//!   [client ns] cli --- rtrc [router ns] rtrs --- srv [sink ns]
//!     10.0.0.5/24        10.0.0.1  10.1.0.1       10.1.0.2/24
//! ```
//!
//! The router enables forwarding and loads two nftables tables on the
//! `forward` hook:
//!   * `inet sng_filter` — the SNG-rendered ruleset (priority `filter`, 0)
//!   * `inet sng_probe`  — a counter-only chain (priority 10, policy accept)
//!
//! Netfilter traverses base chains on a hook in priority order, and a
//! `drop` verdict is final across the whole hook while `accept` only ends
//! the current chain. So a packet the SNG table `drop`s (or that falls to
//! its `policy drop`) never reaches the probe chain, whereas one it
//! `accept`s is counted. The per-packet counter delta is therefore the
//! kernel's verdict: delta > 0 ⇒ accept, delta == 0 ⇒ deny.
//!
//! Privileged: namespaces and `nft` require root, obtained per-command via
//! `sudo -n` (matching [`crate::firewall`]'s `nft -c` path). When sudo/nft
//! are unavailable the function is reported UNTESTED rather than failed, so
//! the harness still runs on an unprivileged box.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sng_fw::{
    EvaluationContext, FirewallEngine, FlowDirection, FlowKey, MockNftables, Protocol, RuleAction,
};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::firewall::{corpus, policy_ruleset};
use crate::report::{Case, FunctionReport, Kind, Targets};

const FN_NAME: &str = "firewall_kernel";
const CRATE: &str = "sng-fw";

/// Deterministic, locally-administered MACs for the four veth endpoints so
/// neighbour entries can be pre-seeded without parsing `ip` output (a
/// pending ARP resolution would otherwise drop the single probe packet).
const MAC_CLI: &str = "02:00:00:00:0c:01";
const MAC_RTRC: &str = "02:00:00:00:0c:02";
const MAC_RTRS: &str = "02:00:00:00:0c:03";
const MAC_SRV: &str = "02:00:00:00:0c:04";

/// nftables observation table installed *after* the SNG ruleset: a
/// counter-only chain on the `forward` hook at a later priority. It counts
/// every packet the SNG table let through, so the counter delta around one
/// probe packet is the kernel verdict.
const PROBE_TABLE: &str = "\
add table inet sng_probe
add counter inet sng_probe fwdctr
add chain inet sng_probe pchain { type filter hook forward priority 10; policy accept; }
add rule inet sng_probe pchain counter name fwdctr
";

/// Run a privileged command via `sudo -n`, returning stdout on success.
async fn sudo_out(args: &[&str]) -> Result<String, String> {
    let out = Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| format!("spawn `sudo {}`: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "`sudo {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Run a privileged command via `sudo -n`, discarding output.
async fn sudo(args: &[&str]) -> Result<(), String> {
    sudo_out(args).await.map(|_| ())
}

/// Feed `input` to `sudo -n <args>` on stdin (used for `nft -f -`).
async fn sudo_stdin(args: &[&str], input: &str) -> Result<(), String> {
    let mut child = Command::new("sudo")
        .arg("-n")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn `sudo {}`: {e}", args.join(" ")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .await
            .map_err(|e| format!("write stdin to `sudo {}`: {e}", args.join(" ")))?;
        stdin
            .shutdown()
            .await
            .map_err(|e| format!("close stdin to `sudo {}`: {e}", args.join(" ")))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait `sudo {}`: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "`sudo {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Tears down the per-run namespaces (and, with them, their veths) on every
/// exit path — success, error, or panic — so a long-lived CI runner never
/// accumulates stale `sngk-*` namespaces.
struct NetnsGuard {
    names: Vec<String>,
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        for n in &self.names {
            let _ = std::process::Command::new("sudo")
                .args(["-n", "ip", "netns", "del", n])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// The throwaway client / router / sink namespace names for this process.
struct Topology {
    cli: String,
    rtr: String,
    srv: String,
}

impl Topology {
    fn new() -> Self {
        let pid = std::process::id();
        Self {
            cli: format!("sngk-cli-{pid}"),
            rtr: format!("sngk-rtr-{pid}"),
            srv: format!("sngk-srv-{pid}"),
        }
    }
}

/// Build the client/router/sink namespaces, veth links, addressing,
/// forwarding and static neighbours. Returns once the data path is ready
/// to carry probe packets.
async fn build_topology(t: &Topology) -> Result<(), String> {
    for ns in [&t.cli, &t.rtr, &t.srv] {
        sudo(&["ip", "netns", "add", ns]).await?;
    }
    // client <-> router and router <-> sink veth pairs, with fixed MACs.
    sudo(&[
        "ip", "link", "add", "cli", "address", MAC_CLI, "netns", &t.cli, "type", "veth", "peer",
        "name", "rtrc", "address", MAC_RTRC, "netns", &t.rtr,
    ])
    .await?;
    sudo(&[
        "ip", "link", "add", "rtrs", "address", MAC_RTRS, "netns", &t.rtr, "type", "veth", "peer",
        "name", "srv", "address", MAC_SRV, "netns", &t.srv,
    ])
    .await?;

    // Addressing + link state.
    sudo(&[
        "ip",
        "-n",
        &t.cli,
        "addr",
        "add",
        "10.0.0.5/24",
        "dev",
        "cli",
    ])
    .await?;
    sudo(&[
        "ip",
        "-n",
        &t.rtr,
        "addr",
        "add",
        "10.0.0.1/24",
        "dev",
        "rtrc",
    ])
    .await?;
    sudo(&[
        "ip",
        "-n",
        &t.rtr,
        "addr",
        "add",
        "10.1.0.1/24",
        "dev",
        "rtrs",
    ])
    .await?;
    sudo(&[
        "ip",
        "-n",
        &t.srv,
        "addr",
        "add",
        "10.1.0.2/24",
        "dev",
        "srv",
    ])
    .await?;
    for (ns, dev) in [
        (&t.cli, "cli"),
        (&t.rtr, "rtrc"),
        (&t.rtr, "rtrs"),
        (&t.srv, "srv"),
    ] {
        sudo(&["ip", "-n", ns, "link", "set", dev, "up"]).await?;
    }
    for ns in [&t.cli, &t.rtr, &t.srv] {
        sudo(&["ip", "-n", ns, "link", "set", "lo", "up"]).await?;
    }

    // Routing: client default via router; router forwards every probe
    // destination out the sink leg; the sink is a pure packet sink (no
    // route back, forwarding off) so an accepted packet is counted exactly
    // once and never loops.
    sudo(&[
        "ip", "-n", &t.cli, "route", "add", "default", "via", "10.0.0.1",
    ])
    .await?;
    sudo(&[
        "ip", "-n", &t.rtr, "route", "add", "default", "via", "10.1.0.2",
    ])
    .await?;
    sudo(&[
        "ip",
        "netns",
        "exec",
        &t.rtr,
        "sysctl",
        "-q",
        "-w",
        "net.ipv4.ip_forward=1",
    ])
    .await?;
    // The probe sources are spoofed corpus addresses on asymmetric paths;
    // disable reverse-path filtering so they are not dropped before the
    // SNG forward chain ever sees them.
    sudo(&[
        "ip",
        "netns",
        "exec",
        &t.rtr,
        "sysctl",
        "-q",
        "-w",
        "net.ipv4.conf.all.rp_filter=0",
    ])
    .await?;
    sudo(&[
        "ip",
        "netns",
        "exec",
        &t.rtr,
        "sysctl",
        "-q",
        "-w",
        "net.ipv4.conf.rtrc.rp_filter=0",
    ])
    .await?;
    sudo(&[
        "ip",
        "netns",
        "exec",
        &t.srv,
        "sysctl",
        "-q",
        "-w",
        "net.ipv4.ip_forward=0",
    ])
    .await?;

    // Static neighbours so the single probe packet is never queued behind
    // an ARP resolution (which would drop it and read as a false `deny`).
    sudo(&[
        "ip", "-n", &t.cli, "neigh", "replace", "10.0.0.1", "lladdr", MAC_RTRC, "dev", "cli",
    ])
    .await?;
    sudo(&[
        "ip", "-n", &t.rtr, "neigh", "replace", "10.1.0.2", "lladdr", MAC_SRV, "dev", "rtrs",
    ])
    .await?;
    Ok(())
}

/// Read the cumulative `sng_probe` forward counter (packets) in the router
/// namespace.
async fn probe_packets(rtr: &str) -> Result<u64, String> {
    let text = sudo_out(&[
        "ip",
        "netns",
        "exec",
        rtr,
        "nft",
        "list",
        "counter",
        "inet",
        "sng_probe",
        "fwdctr",
    ])
    .await?;
    // `... counter fwdctr { packets N bytes M }`
    let n = text
        .split("packets")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("could not parse probe counter from: {}", text.trim()))?;
    Ok(n)
}

/// Emit one probe packet matching `flow` from the client namespace by
/// re-executing this binary's hidden `--send-raw` sender as root inside the
/// namespace (keeps packet crafting in-process and dependency-free).
async fn send_probe(cli: &str, exe: &str, flow: &ProbeFlow) -> Result<(), String> {
    let proto = match flow.proto {
        Protocol::Udp => "udp",
        _ => "tcp",
    };
    let dport = flow.dport.to_string();
    let src = flow.src.to_string();
    let dst = flow.dst.to_string();
    sudo(&[
        "ip",
        "netns",
        "exec",
        cli,
        exe,
        "--send-raw",
        &src,
        &dst,
        &dport,
        proto,
    ])
    .await
}

/// Kernel verdict for one forwarded probe: send it, then watch the probe
/// counter. An accepted packet bumps the counter within a few tens of ms;
/// a dropped one never does. Poll briefly so accepts return fast while
/// drops still settle deterministically.
async fn kernel_accepts(rtr: &str, cli: &str, exe: &str, flow: &ProbeFlow) -> Result<bool, String> {
    let before = probe_packets(rtr).await?;
    send_probe(cli, exe, flow).await?;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        if probe_packets(rtr).await? > before {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The subset of a corpus [`crate::firewall::FlowCase`] this driver needs,
/// reduced to IPv4 (the corpus is all IPv4; the netns data path is IPv4).
struct ProbeFlow {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dport: u16,
    proto: Protocol,
}

fn as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}

/// Preflight: confirm we can actually drive netns + nft before tearing into
/// the corpus. Returns an UNTESTED reason string when the environment can't
/// support the check.
async fn preflight() -> Result<(), String> {
    // Passwordless sudo for the privileged path.
    if sudo(&["true"]).await.is_err() {
        return Err(
            "passwordless sudo unavailable; kernel nftables conformance needs root \
                    for network namespaces and nft"
                .into(),
        );
    }
    if sudo(&["nft", "--version"]).await.is_err() {
        return Err(
            "nft not runnable under sudo; install nftables to verify kernel \
                    enforcement (apt install nftables)"
                .into(),
        );
    }
    if sudo(&["ip", "-V"]).await.is_err() {
        return Err(
            "iproute2 `ip` not runnable under sudo; required for network namespaces".into(),
        );
    }
    Ok(())
}

pub async fn run() -> FunctionReport {
    if let Err(reason) = preflight().await {
        return FunctionReport::untested(FN_NAME, CRATE, Kind::Enforcement, &reason);
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            return FunctionReport::untested(
                FN_NAME,
                CRATE,
                Kind::Enforcement,
                &format!("cannot resolve own executable for the in-namespace sender: {e}"),
            );
        }
    };

    // Userspace source of truth: the same ruleset, evaluated in-memory.
    let ruleset = policy_ruleset();
    let engine = FirewallEngine::new(Arc::new(MockNftables::new()));
    if let Err(e) = engine.install(ruleset.clone()).await {
        return FunctionReport::untested(
            FN_NAME,
            CRATE,
            Kind::Enforcement,
            &format!("could not install userspace ruleset for comparison: {e}"),
        );
    }
    let script = match ruleset.script.as_str() {
        Some(s) => s.to_string(),
        None => {
            return FunctionReport::untested(
                FN_NAME,
                CRATE,
                Kind::Enforcement,
                "SNG-rendered nftables script was not valid UTF-8",
            );
        }
    };

    let topo = Topology::new();
    let _guard = NetnsGuard {
        names: vec![topo.cli.clone(), topo.rtr.clone(), topo.srv.clone()],
    };

    if let Err(e) = build_topology(&topo).await {
        return FunctionReport::untested(
            FN_NAME,
            CRATE,
            Kind::Enforcement,
            &format!("failed to build kernel test topology: {e}"),
        );
    }

    // Load the SNG-rendered ruleset, then the observation table, into the
    // router namespace.
    if let Err(e) = sudo_stdin(
        &["ip", "netns", "exec", &topo.rtr, "nft", "-f", "-"],
        &script,
    )
    .await
    {
        return FunctionReport::untested(
            FN_NAME,
            CRATE,
            Kind::Enforcement,
            &format!("kernel rejected the SNG-rendered ruleset on load: {e}"),
        );
    }
    if let Err(e) = sudo_stdin(
        &["ip", "netns", "exec", &topo.rtr, "nft", "-f", "-"],
        PROBE_TABLE,
    )
    .await
    {
        return FunctionReport::untested(
            FN_NAME,
            CRATE,
            Kind::Enforcement,
            &format!("could not install nftables probe counter: {e}"),
        );
    }

    let mut cases = Vec::new();
    let mut divergences: Vec<String> = Vec::new();
    for f in corpus() {
        let (Some(src), Some(dst)) = (as_v4(f.src), as_v4(f.dst)) else {
            return FunctionReport::untested(
                FN_NAME,
                CRATE,
                Kind::Enforcement,
                "corpus flow is not IPv4; the kernel netns data path is IPv4-only",
            );
        };
        let flow = ProbeFlow {
            src,
            dst,
            dport: f.dport,
            proto: f.proto,
        };

        // Userspace verdict from the in-memory engine.
        let us = engine.evaluate(&EvaluationContext {
            flow: FlowKey::new(f.src, f.dst, 33333, f.dport, f.proto),
            direction: FlowDirection::Original,
            subject_value: None,
        });
        let us_deny = us.action == RuleAction::Deny;

        // Kernel verdict from the rendered nftables ruleset.
        let kernel_accept = match kernel_accepts(&topo.rtr, &topo.cli, &exe, &flow).await {
            Ok(v) => v,
            Err(e) => {
                // A measurement failure is not a verdict: fabricating one
                // would silently corrupt the confusion matrix. Report the
                // whole function UNTESTED instead (mirrors the IPS driver).
                return FunctionReport::untested(
                    FN_NAME,
                    CRATE,
                    Kind::Enforcement,
                    &format!("kernel probe failed for {}: {e}", f.desc),
                );
            }
        };
        let kernel_deny = !kernel_accept;

        if kernel_deny != us_deny {
            divergences.push(format!(
                "{}: userspace={} kernel={}",
                f.desc,
                if us_deny { "deny" } else { "allow" },
                if kernel_deny { "deny" } else { "allow" },
            ));
        }

        // A case is correct only when the kernel matches the userspace
        // engine AND the expected disposition (bad ⇒ deny, good ⇒ allow).
        let expected_deny = f.bad;
        let correct = kernel_deny == us_deny && kernel_deny == expected_deny;
        cases.push(Case {
            description: f.desc.into(),
            bad: f.bad,
            expected: if expected_deny { "deny" } else { "allow" }.into(),
            actual: if kernel_deny { "deny" } else { "allow" }.into(),
            correct,
        });
    }

    let notes = if divergences.is_empty() {
        format!(
            "Kernel nftables enforcement matches the userspace engine on all {} corpus flows: \
             the SNG-rendered ruleset was installed in a network namespace and each flow's \
             verdict was read back from the kernel forward path (veth + counter). No \
             kernel/userspace divergence.",
            cases.len()
        )
    } else {
        format!(
            "KERNEL/USERSPACE DIVERGENCE on {} of {} flows (renderer bug): {}",
            divergences.len(),
            cases.len(),
            divergences.join("; ")
        )
    };

    FunctionReport::from_cases(
        FN_NAME,
        CRATE,
        Kind::Enforcement,
        Targets::default(),
        cases,
        Some(notes),
    )
}

/// Craft a minimal IPv4 TCP-SYN / UDP datagram for `(src, dst, dport)` and
/// emit it on a raw socket. Run as root inside the client namespace via the
/// hidden `--send-raw` CLI path; the packet then traverses the router's
/// `forward` hook exactly like real client egress.
///
/// nftables matches on header fields (`meta l4proto`, `th dport`, `ip
/// daddr`), not L4 checksums, so the L4 checksum is left zero; the IPv4
/// header checksum is computed for correctness.
#[cfg(target_os = "linux")]
pub fn send_raw(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, proto: Protocol) -> std::io::Result<()> {
    const SPORT: u16 = 33333;
    let proto_num: u8 = match proto {
        Protocol::Udp => 17,
        _ => 6,
    };

    let l4: Vec<u8> = match proto {
        Protocol::Udp => {
            let payload = [b'x'];
            let len = (8 + payload.len()) as u16;
            let mut u = Vec::with_capacity(len as usize);
            u.extend_from_slice(&SPORT.to_be_bytes());
            u.extend_from_slice(&dport.to_be_bytes());
            u.extend_from_slice(&len.to_be_bytes());
            u.extend_from_slice(&0u16.to_be_bytes()); // checksum (optional for IPv4 UDP)
            u.extend_from_slice(&payload);
            u
        }
        _ => {
            let mut t = Vec::with_capacity(20);
            t.extend_from_slice(&SPORT.to_be_bytes());
            t.extend_from_slice(&dport.to_be_bytes());
            t.extend_from_slice(&0u32.to_be_bytes()); // seq
            t.extend_from_slice(&0u32.to_be_bytes()); // ack
            t.push(5 << 4); // data offset = 5 words, no flags in low nibble
            t.push(0x02); // SYN
            t.extend_from_slice(&1024u16.to_be_bytes()); // window
            t.extend_from_slice(&0u16.to_be_bytes()); // checksum
            t.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr
            t
        }
    };

    let total_len = (20 + l4.len()) as u16;
    let mut ip = Vec::with_capacity(total_len as usize);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // identification
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    ip.push(64); // TTL
    ip.push(proto_num);
    ip.extend_from_slice(&0u16.to_be_bytes()); // header checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let csum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&l4);

    // SAFETY: the libc socket/sendto/close calls below use only locals and a
    // properly initialised `sockaddr_in`; the buffer pointer/length come
    // from `ip` which outlives the call.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
        let sent = libc::sendto(
            fd,
            ip.as_ptr().cast(),
            ip.len(),
            0,
            std::ptr::addr_of!(addr).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if sent < 0 {
            return Err(err);
        }
    }
    Ok(())
}

/// Standard one's-complement IPv4 header checksum.
#[cfg(target_os = "linux")]
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
        i += 2;
    }
    if i < header.len() {
        sum += u32::from(header[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn ipv4_checksum_matches_rfc1071_reference() {
        // Canonical RFC 1071 worked example header; the checksum field is
        // zero and the routine must reproduce the documented 0xb861.
        let header = [
            0x45u8, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(ipv4_checksum(&header), 0xb861);
    }

    #[test]
    fn ipv4_checksum_over_header_is_self_verifying() {
        // Inserting the computed checksum back into the header makes the
        // one's-complement sum fold to zero (the receiver's check).
        let mut header = [
            0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x05, 0x0a, 0x01, 0x00, 0x02,
        ];
        let csum = ipv4_checksum(&header);
        header[10..12].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(ipv4_checksum(&header), 0);
    }

    #[test]
    fn as_v4_extracts_ipv4_and_rejects_ipv6() {
        assert_eq!(
            as_v4(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(as_v4("::1".parse().unwrap()), None);
    }
}
