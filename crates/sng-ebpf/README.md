# `sng-ebpf`

eBPF/XDP fast-path data plane for the ShieldNet Gateway edge VM.

The default packet path is nftables + conntrack (`sng-fw`); this crate is
the opt-in accelerator ARCHITECTURE.md §4.1 reserves for when measured
throughput demand justifies the operational cost. It provides:

- **XDP ingress** — packet classification into the six
  `docs/TRAFFIC_CLASSIFICATION.md` traffic-class tiers plus hot-path
  L3/L4 firewall evaluation, dropping or accepting at the earliest kernel
  hook.
- **TC egress** — per-traffic-class steering onto the correct underlay
  (default route, marked policy route, SD-WAN / cloud-connector
  redirect).
- **BPF maps** — per-flow state, an XDP-side conntrack shadow, and a TTL
  policy-verdict cache so repeat packets skip re-evaluation.
- **Userspace control plane** — loads, attaches, pins, and updates the
  kernel programs and maps.

## Userspace vs. kernel

The kernel programs are a separate `no_std` BPF compilation unit produced
by the appliance image pipeline, **not** by `cargo build --workspace`.
This crate is the userspace half: all types, the classification and
rule-evaluation logic, the map models, and the control plane.

Everything compiles and unit-tests on any target with no eBPF toolchain
or kernel present. The real kernel loader (`aya`) is behind the **`xdp`**
feature (Linux-only). With the feature off — the default — the control
plane runs over an in-memory `NoopLoader` that models every map in
userspace, so the firewall crate's `EbpfBackend` is fully exercisable in
CI and the workspace build never depends on an eBPF environment.

```text
cargo build  -p sng-ebpf                 # userspace model, any target
cargo test   -p sng-ebpf                 # unit tests, no kernel needed
cargo build  -p sng-ebpf --features xdp  # + aya kernel loader (Linux)
```
