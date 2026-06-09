# sng-mobile-sdk

The single **UniFFI binding layer** an iOS (Swift) or Android (Kotlin)
app links against to drive the ShieldNet Gateway mobile agent. This
crate is **glue + FFI only**: it composes the already-built mobile
pieces and exposes them through a stable foreign-function interface,
adding no new agent behaviour.

```text
  Swift / Kotlin app
         │  (UniFFI bindings: .swift / .kt + C header)
         ▼
  ┌──────────────────────┐
  │  sng-mobile-sdk      │  this crate: FFI surface + assembly
  │   MobileSdk (Object) │
  └──────────┼───────────┘
             ▼
   sng-mobile-core::MobileAgent
      ▲          ▲          ▲
      │          │          │
  PAL traits   sng-oidc   PolicyTrustStore
 (ios/android  (AuthSession)  (sng-comms)
  /host fallback)
```

## What it composes (does not reimplement)

* [`sng-mobile-core`](../sng-mobile-core) — the platform-agnostic
  agent brain (`MobileAgent`, lifecycle, enrolment, posture,
  telemetry, ZTNA). Driven, never duplicated.
* `sng-mobile-pal-ios` / `sng-mobile-pal-android` — the concrete
  `SecureKeyStore` / `MobilePostureCollector` / `MobileTunnelProvider`
  / `AuthSurface` backings. They enter the build graph **only** under
  `cfg(target_os = "ios" | "android")` (see `Cargo.toml` `[target.…]`).
* [`sng-oidc`](../sng-oidc) — the pure-Rust OIDC client (discovery,
  PKCE, token exchange, ID-token validation), wired into an
  `AuthSession` by `oidc::OidcAuthSession`.

## Platform selection & the Linux host fallback

`deps::assemble` picks the iOS PAL on `cfg(target_os = "ios")`, the
Android PAL on `cfg(target_os = "android")`, and the typed-Unsupported
`host` fallback on every other target (Linux CI, desktop). The host
fallback implements every platform trait but returns each trait's own
"unsupported on this platform" error — **never a fake success** — so
the whole workspace compiles, clippy-passes, and unit-tests on Linux
while a desktop build can never behave as if it had a secure enclave
or a tunnel.

## Exported foreign API surface

| Kind | Name | Notes |
|---|---|---|
| Object | `MobileSdk` | Opaque handle wrapping `MobileAgent` + OIDC session. Constructed from `SdkMobileConfig`. |
| Record | `SdkMobileConfig` | Top-level config; ids, control-plane URL, intervals (`*_secs` / `*_ms`), OIDC `oidc_redirect_uri`, `auth`, `trust_anchors`. |
| Record | `SdkAuthConfig` | OIDC issuer, client id, scopes, refresh skew/jitter. |
| Record | `SdkTrustAnchor` | Ed25519 policy-signing public key (`key_id` + base64). |
| Record | `SdkAgentHealth`, `SdkPostureSnapshot`, `SdkEnrollmentOutcome` | Owned, secret-free projections; timestamps as `i64` epoch-ms. `SdkAgentHealth` includes the current `power` state. |
| Enum | `SdkLifecycleState`, `SdkAuthState`, `SdkTunnelStatus`, `SdkPlatform`, `SdkPowerState` | FFI-safe mirrors of the core enums. |
| Error | `MobileSdkError` | Flat, owned error contract; one `description: String` per variant. |

### `MobileSdk` methods

* Sync: `state`, `health`, `auth_state`, `is_authenticated`,
  `last_posture`, `power_state`, `set_power_state`, `suspend`,
  `resume`, `terminate`.
* Async (`async_runtime = "tokio"`): `enroll(claim_token)`,
  `collect_posture`, `sign_in`, `refresh_auth`.

### Battery-aware scheduling

The agent coalesces its policy-pull / telemetry-flush / posture timers
into a single wakeup. `set_power_state(SdkPowerState::LowPower)`
stretches that wakeup **4×** (see
`sng_mobile_core::LOW_POWER_INTERVAL_MULTIPLIER`) to cut radio wakeups
on battery saver; `SdkPowerState::Normal` restores the configured
cadence. It is a *push* signal — wire it to the platform notification
(iOS `ProcessInfo.isLowPowerModeEnabled` /
`NSProcessInfoPowerStateDidChange`, Android
`PowerManager.isPowerSaveMode` / `ACTION_POWER_SAVE_MODE_CHANGED`); the
agent never polls a battery API itself. The change takes effect
immediately, even mid-sleep.

A typical drive is: `new(config)` → `sign_in` → `enroll(claim_token)`
→ steady state (`collect_posture`, `refresh_auth`) →
`suspend`/`resume` → `terminate`.

## `unsafe_code` posture

The crate inherits the workspace `unsafe_code = "deny"` lint and adds
**no** `#[allow(unsafe_code)]` overrides. UniFFI proc-macro mode
(`uniffi::setup_scaffolding!()` + `#[uniffi::export]`, no UDL, no
`build.rs`) confines all `unsafe` inside macro-generated code that
carries its own allow; this crate's own source is entirely
`unsafe`-free (verified under
`cargo clippy --all-targets -- -D warnings`).

## Generating the Swift + Kotlin bindings

The foreign-language source is **target-independent** and is generated
from a compiled `cdylib` via UniFFI's `generate --library` mode (it
reads the metadata `setup_scaffolding!()` embeds in the library). A
sibling binary crate [`sng-uniffi-bindgen`](../sng-uniffi-bindgen)
wraps `uniffi::uniffi_bindgen_main()`.

```sh
# regenerates Swift + Kotlin into crates/sng-mobile-sdk/bindings/generated/
crates/sng-mobile-sdk/bindings/generate.sh            # release (optimized)
crates/sng-mobile-sdk/bindings/generate.sh debug      # or a debug build
```

Equivalent manual invocation:

```sh
# NOTE: [profile.release] sets strip = true, which removes the symbols
# the generator reads — override it so the metadata survives.
cargo build -p sng-mobile-sdk --release --config profile.release.strip=false
cargo run  -p sng-uniffi-bindgen -- generate \
  --library target/release/libsng_mobile_sdk.so \
  --language swift  --out-dir crates/sng-mobile-sdk/bindings/generated
cargo run  -p sng-uniffi-bindgen -- generate \
  --library target/release/libsng_mobile_sdk.so \
  --language kotlin --out-dir crates/sng-mobile-sdk/bindings/generated
```

Generated output is git-ignored (regenerate it; never hand-edit).
Produces: `sng_mobile_sdk.swift`, `sng_mobile_sdkFFI.h`,
`sng_mobile_sdkFFI.modulemap`, and `uniffi/sng_mobile_sdk/sng_mobile_sdk.kt`.

### iOS packaging — Swift Package + `.xcframework`

The [`apple/`](apple) directory is a ready-to-resolve Swift Package
(`ShieldNetMobile`) wrapping an `XCFramework` of the crate's
`staticlib`. On a macOS host with Xcode:

```sh
crates/sng-mobile-sdk/apple/scripts/build-xcframework.sh   # release
```

The script regenerates the bindings, cross-compiles the device +
simulator slices, assembles `sng_mobile_sdkFFI.xcframework`, and copies
the generated Swift into the package. See [`apple/README.md`](apple/README.md).

### Android packaging — Gradle module + `.aar`

The [`android/`](android) directory is a Gradle Android library module
that packages the generated Kotlin + per-ABI `cdylib`s into an `.aar`.
With the Android SDK + NDK and `cargo-ndk`:

```sh
crates/sng-mobile-sdk/android/scripts/build-aar.sh         # release
```

The script regenerates the bindings, builds `libsng_mobile_sdk.so` for
`arm64-v8a` / `armeabi-v7a` / `x86_64` with cargo-ndk, and runs
`./gradlew assembleRelease`. The generated Kotlin loads the native
library via JNA (shipped transitively as `net.java.dev.jna:jna@aar`).
See [`android/README.md`](android/README.md).

### CI

[`.github/workflows/mobile-sdk.yml`](../../.github/workflows/mobile-sdk.yml)
verifies binding generation on Linux, then builds + uploads the Swift
Package (`XCFramework`) on macOS and the `.aar` on Linux as artifacts.

## Local verification

```sh
cargo +1.91 test   -p sng-mobile-sdk --all-targets
cargo +1.91 clippy -p sng-mobile-sdk --all-targets -- -D warnings
cargo +1.91 fmt    --all -- --check
```
