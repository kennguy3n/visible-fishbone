# ShieldNet Gateway mobile SDK — Android Archive (.aar)

The Android distribution of [`sng-mobile-sdk`](../README.md): a Gradle
Android library module that packages the UniFFI-generated Kotlin
(`uniffi.sng_mobile_sdk`) together with the per-ABI native libraries.

## Layout

```text
android/
  build.gradle.kts                 # AGP library module (committed)
  settings.gradle.kts              # repositories + root project (committed)
  gradle.properties                # AndroidX + JVM args (committed)
  consumer-rules.pro               # R8 keep rules shipped in the AAR (committed)
  gradlew / gradle/wrapper/...      # pinned Gradle wrapper (committed)
  src/main/AndroidManifest.xml     # library manifest (committed)
  src/main/kotlin/uniffi/...        # generated Kotlin (git-ignored)
  src/main/jniLibs/<abi>/...        # cargo-ndk .so output (git-ignored)
  scripts/build-aar.sh             # builds the two above + the AAR
```

The Gradle project and `consumer-rules.pro` are committed. The
generated Kotlin and the `.so`s are **build artifacts**: run the build
script (or the CI job) before assembling. CI builds and uploads the
AAR — see
[`.github/workflows/mobile-sdk.yml`](../../../.github/workflows/mobile-sdk.yml).

## Build (Android SDK + NDK host)

Prerequisites: the Android SDK + NDK (`ANDROID_HOME` / `ANDROID_NDK_HOME`),
[`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk), and the Rust
Android targets:

```sh
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
crates/sng-mobile-sdk/android/scripts/build-aar.sh         # release
```

The script regenerates the bindings, copies the Kotlin into the source
set, builds `libsng_mobile_sdk.so` for `arm64-v8a`, `armeabi-v7a`, and
`x86_64` into `jniLibs/`, and runs `./gradlew assembleRelease`. The AAR
lands in `build/outputs/aar/`.

## Consume

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
```

```kotlin
import uniffi.sng_mobile_sdk.MobileSdk
import uniffi.sng_mobile_sdk.SdkPowerState

val sdk = MobileSdk(config)
sdk.setPowerState(SdkPowerState.LOW_POWER)   // stretch the heartbeat 4× on power-save
val health = sdk.health()
```

JNA (pulled transitively as `net.java.dev.jna:jna@aar`) loads the
native `libsng_mobile_sdk.so` the generated Kotlin binds to.
