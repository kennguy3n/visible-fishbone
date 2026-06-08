//! `sng-bench-datapath` — nftables vs eBPF/XDP decision-throughput
//! micro-benchmark.
//!
//! Unlike the main `sng-bench` harness, this binary needs no NIC, no
//! root, and no running gateway: it builds a synthetic L3/L4 rule set
//! and packet stream and times the two enforcement substrates'
//! per-packet decision loops in-process (see [`sng_bench::datapath`]).
//!
//! Usage:
//! ```text
//! sng-bench-datapath [RULES] [PACKETS]
//! ```
//! Defaults: 256 rules, 500_000 packets. Prints a human-readable
//! table and a single JSON object (so a CI step can capture the
//! speedup without parsing prose).

use std::process::ExitCode;

use sng_bench::datapath::{self, DataPathComparison, DdosBenchResult};

const DEFAULT_RULES: usize = 256;
const DEFAULT_PACKETS: usize = 500_000;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let rules = match parse_arg(args.next(), DEFAULT_RULES) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let packets = match parse_arg(args.next(), DEFAULT_PACKETS) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    let cmp = datapath::compare(rules, packets);
    print_report(&cmp);

    let ddos = datapath::bench_syn_flood_drop_rate(packets);
    print_ddos_report(&ddos);
    ExitCode::SUCCESS
}

fn parse_arg(arg: Option<String>, default: usize) -> Result<usize, String> {
    match arg {
        None => Ok(default),
        Some(s) => s
            .parse::<usize>()
            .map_err(|e| format!("invalid count {s:?}: {e}"))
            .and_then(|v| {
                if v == 0 {
                    Err("count must be > 0".to_owned())
                } else {
                    Ok(v)
                }
            }),
    }
}

fn print_report(cmp: &DataPathComparison) {
    let nft = cmp.nftables.packets_per_sec();
    let ebpf = cmp.ebpf.packets_per_sec();
    println!("ShieldNet Gateway data-path throughput: nftables vs eBPF/XDP");
    println!("  rules           : {}", cmp.rule_count);
    println!("  packets / path  : {}", cmp.nftables.packets);
    println!(
        "  nftables (slow) : {:>14.0} pkt/s   ({:?})",
        nft, cmp.nftables.elapsed
    );
    println!(
        "  eBPF/XDP (fast) : {:>14.0} pkt/s   ({:?})",
        ebpf, cmp.ebpf.elapsed
    );
    println!("  speedup         : {:.2}x", cmp.speedup());
    // Machine-readable line for CI capture.
    println!(
        "{{\"rules\":{},\"packets\":{},\"nftables_pps\":{:.3},\"ebpf_pps\":{:.3},\"speedup\":{:.3}}}",
        cmp.rule_count,
        cmp.nftables.packets,
        nft,
        ebpf,
        cmp.speedup()
    );
}

fn print_ddos_report(ddos: &DdosBenchResult) {
    let pps = ddos.packets_per_sec();
    println!();
    println!("ShieldNet Gateway XDP SYN-flood mitigation drop rate");
    println!("  packets         : {}", ddos.packets);
    println!(
        "  dropped         : {} ({:.1}%)",
        ddos.dropped,
        ddos.drop_ratio() * 100.0
    );
    println!(
        "  drop decision   : {:>14.0} pkt/s   ({:?})",
        pps, ddos.elapsed
    );
    println!(
        "  vs 10M pps target: {}",
        if pps >= 10_000_000.0 { "MET" } else { "below" }
    );
    // Machine-readable line for CI capture.
    println!(
        "{{\"ddos_packets\":{},\"ddos_dropped\":{},\"ddos_drop_pps\":{:.3},\"ddos_drop_ratio\":{:.3}}}",
        ddos.packets,
        ddos.dropped,
        pps,
        ddos.drop_ratio()
    );
}
