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
| Record | `SdkAgentHealth`, `SdkPostureSnapshot`, `SdkEnrollmentOutcome` | Owned, secret-free projections; timestamps as `i64` epoch-ms. |
| Enum | `SdkLifecycleState`, `SdkAuthState`, `SdkTunnelStatus`, `SdkPlatform` | FFI-safe mirrors of the core enums. |
| Error | `MobileSdkError` | Flat, owned error contract; one `description: String` per variant. |

### `MobileSdk` methods

* Sync: `state`, `health`, `auth_state`, `is_authenticated`,
  `last_posture`, `suspend`, `resume`, `terminate`.
* Async (`async_runtime = "tokio"`): `enroll(claim_token)`,
  `collect_posture`, `sign_in`, `refresh_auth`.

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

### iOS packaging (`.xcframework`)

The crate already builds a `staticlib`. On a macOS host with the Rust
Apple targets installed, build the static lib for device + simulator
and assemble an `.xcframework` around the generated header/modulemap:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
for T in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build -p sng-mobile-sdk --release --target "$T"
done
# (lipo the simulator archs as needed, then:)
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libsng_mobile_sdk.a \
  -headers crates/sng-mobile-sdk/bindings/generated \
  -library target/aarch64-apple-ios-sim/release/libsng_mobile_sdk.a \
  -headers crates/sng-mobile-sdk/bindings/generated \
  -output SngMobileSdk.xcframework
```

Drop `SngMobileSdk.xcframework` and `sng_mobile_sdk.swift` into a Swift
Package / Xcode project. The modulemap names the FFI module
`sng_mobile_sdkFFI`, which the Swift source imports.

### Android packaging (`.aar`)

The crate builds a `cdylib`. With the Android NDK targets installed,
build the `.so` per ABI and place them under an AAR's `jniLibs`
alongside the generated Kotlin:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
# build each with cargo-ndk (or a linker-configured cargo build), e.g.:
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o android/src/main/jniLibs build -p sng-mobile-sdk --release
# copy uniffi/sng_mobile_sdk/sng_mobile_sdk.kt into the module source set,
# then assemble the AAR with Gradle.
```

The generated Kotlin loads the native library via JNA; ship JNA on the
Android classpath (UniFFI's Kotlin runtime dependency).

## Local verification

```sh
cargo +1.85 test   -p sng-mobile-sdk --all-targets
cargo +1.85 clippy -p sng-mobile-sdk --all-targets -- -D warnings
cargo +1.85 fmt    --all -- --check
```
