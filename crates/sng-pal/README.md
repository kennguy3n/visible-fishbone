# sng-pal

Platform Abstraction Layer for the ShieldNet Gateway edge / endpoint
workspace. Defines OS-agnostic traits over the kernel hooks SNG depends
on, plus per-OS implementations behind `cfg(target_os = "…")`.

Trait surface:

- **`TrafficCapture`** — bind to a network interface and emit raw
  packets (Linux nftables/TPROXY, macOS Network Extension, Windows WFP).
- **`PostureCollector`** — produce a typed posture snapshot (disk
  encryption status, firewall state, screen-lock state, OS patch
  level).
- **`TunnelProvider`** — bring up / tear down a WireGuard-class
  tunnel to the configured peer.
- **`SecureKeyStore`** — generate / use device-bound Ed25519 keys
  backed by the platform's secure element (TPM 2.0 on Windows, Secure
  Enclave on macOS, kernel keyring + TPM-trusted hardware on Linux).
- **`SystemInfo`** — hostname, OS name + version, architecture, basic
  hardware info.

Resource budget primitives — `MemoryBudget(15 MB)`, `CpuBudget(0.1 % idle)`
— are exported from this crate so every PAL backend can validate that
its implementation does not exceed the agent's posted ceilings.

The crate is `#![forbid(unsafe_code)]` at the workspace level. Per-OS
modules that require an unsafe syscall lift the ban locally with a
documented rationale.
