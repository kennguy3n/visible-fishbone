# `sng-ebpf-bpf` — kernel-space XDP/TC data plane

This crate is the **kernel half** of the SNG eBPF fast path. It compiles
to a single BPF object containing two programs and the maps they share
with the userspace control plane in [`crates/sng-ebpf`](../).

| Program            | Hook        | Role                                                            |
| ------------------ | ----------- | --------------------------------------------------------------- |
| `sng_xdp_classify` | XDP ingress | GeoIP block, SYN/UDP flood rate-limit, classify, hot-path firewall, verdict cache + per-flow state |
| `sng_tc_egress`    | TC egress (`clsact`) | Resolve the flow's class tag and steer onto the right underlay (pass / mark / redirect / drop) |

## Why it is a standalone crate

It is **not** a member of the root workspace. It is `no_std`, has no
`main`, and is cross-compiled for a BPF target (`bpfel-unknown-none`) with
a nightly toolchain and `bpf-linker` — none of which the host workspace
build (`cargo build --workspace`) can or should do. The crate declares its
own `[workspace]` table and the root `Cargo.toml` lists it under
`exclude`, so host-side cargo never tries to resolve or compile it.

## The map contract

Every map name, capacity, and `#[repr(C)]` layout in [`src/contract.rs`](src/contract.rs)
is the byte-for-byte mirror of the userspace definitions in
`crates/sng-ebpf/src/wire.rs` and `crates/sng-ebpf/src/maps.rs`. The
userspace loader (`crates/sng-ebpf/src/loader.rs`, `AyaLoader`) marshals
policy into these layouts and writes them into the maps this object
declares; the programs here read them back. **If you change a layout on
one side, change it on the other** — the userspace side pins the sizes in
`wire::tests::wire_layouts_are_padded_and_aligned`.

The program names (`sng_xdp_classify`, `sng_tc_egress`) are the contract
the loader's `program_mut(...)` lookups depend on; do not rename them
without updating `loader.rs`.

## Building (appliance image pipeline)

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker            # links via rustc's bundled LLVM
                                    # (aya-rustc-llvm-proxy); no separate
                                    # system LLVM install is required

cd crates/sng-ebpf/bpf
cargo +nightly build --release
# -> target/bpfel-unknown-none/release/sng-ebpf-bpf
```

The object is a real BPF ELF: `sng_xdp_classify` lands in the `xdp`
section and `sng_tc_egress` in the `classifier` section, with the shared
map definitions in `maps`. None of the data-path arithmetic may use
128-bit math: the BPF target cannot provide `__multi3`, so overflow-checked
or widening 64-bit multiplies (`u64::checked/saturating_mul`, the
`a > u64::MAX / b` overflow idiom, and divide-by-*constant* — which LLVM
lowers to a 64×64→128 magic-number multiply) must be avoided. Divide only
by runtime values (see `bucket_admit`).

The resulting object is published into the appliance image. At runtime the
userspace loader locates it via the `SNG_EBPF_OBJECT` environment variable
(see `AyaLoader` in `crates/sng-ebpf/src/loader.rs`) and loads it with
`aya::Ebpf::load_file`.

To type-check without the linker (CI / local dev where `bpf-linker` is
unavailable):

```sh
cd crates/sng-ebpf/bpf
cargo +nightly check        # compiles for bpfel-unknown-none, no link step
cargo +nightly clippy
```

The `rust-ebpf` CI job (`.github/workflows/ci.yml`) runs exactly these two
commands plus the `--features xdp` lint/test of the userspace loader, so a
type/layout drift in the kernel object or the feature-gated loader is caught
on every PR even though this crate is excluded from the host workspace.
