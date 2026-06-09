#!/usr/bin/env bash
# Build the ShieldNet Gateway mobile SDK Android Archive (.aar).
#
# Pipeline:
#   1. Regenerate the UniFFI bindings (delegates to the repo's
#      bindings/generate.sh) and copy the generated Kotlin into the
#      module's source set.
#   2. Cross-compile the crate's `cdylib` for each Android ABI with
#      `cargo-ndk`, placing the `.so`s under `src/main/jniLibs/`.
#   3. Assemble the AAR with the Gradle wrapper, selecting the
#      release/debug variant to match the cargo profile.
#
# The generated Kotlin and the `.so`s are git-ignored build outputs.
#
# Usage:
#   crates/sng-mobile-sdk/android/scripts/build-aar.sh [PROFILE]
#     PROFILE  cargo profile to build with (default: release)
#
# Requires the Android SDK + NDK (ANDROID_NDK_HOME or ANDROID_HOME),
# `cargo-ndk`, and the Rust Android targets. CI installs these (see
# .github/workflows/mobile-sdk.yml).
set -euo pipefail

PROFILE="${1:-release}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ANDROID_DIR/../../.." && pwd)"

GENERATED_DIR="$REPO_ROOT/crates/sng-mobile-sdk/bindings/generated"
KOTLIN_SRC="$GENERATED_DIR/uniffi"
KOTLIN_DEST="$ANDROID_DIR/src/main/kotlin/uniffi"
JNILIBS_DIR="$ANDROID_DIR/src/main/jniLibs"

# Android ABIs, the cargo `--release`/`--profile` flag, and the matching
# Gradle assemble task. The Gradle variant must track the native build so a
# `debug` invocation produces a debug AAR (debug `.so`s) rather than an AAR
# named "release" that actually carries debug libraries.
ABIS=("arm64-v8a" "armeabi-v7a" "x86_64")
case "$PROFILE" in
  release)   NDK_BUILD_FLAGS=(--release)             ; GRADLE_TASK=assembleRelease ;;
  dev|debug) NDK_BUILD_FLAGS=()                      ; GRADLE_TASK=assembleDebug ;;
  *)         NDK_BUILD_FLAGS=(--profile "$PROFILE")  ; GRADLE_TASK=assembleRelease ;;
esac

cd "$REPO_ROOT"

echo "==> regenerating UniFFI bindings"
"$REPO_ROOT/crates/sng-mobile-sdk/bindings/generate.sh" "$PROFILE" "$GENERATED_DIR"

echo "==> copying generated Kotlin into the module"
rm -rf "$KOTLIN_DEST"
mkdir -p "$(dirname "$KOTLIN_DEST")"
cp -R "$KOTLIN_SRC" "$KOTLIN_DEST"

echo "==> building cdylib per ABI with cargo-ndk"
NDK_TARGET_FLAGS=()
for ABI in "${ABIS[@]}"; do
  NDK_TARGET_FLAGS+=(-t "$ABI")
done
rm -rf "$JNILIBS_DIR"
mkdir -p "$JNILIBS_DIR"
cargo ndk "${NDK_TARGET_FLAGS[@]}" -o "$JNILIBS_DIR" \
  build -p sng-mobile-sdk "${NDK_BUILD_FLAGS[@]}"

echo "==> assembling the AAR ($GRADLE_TASK)"
cd "$ANDROID_DIR"
./gradlew --no-daemon "$GRADLE_TASK"

echo "==> done; AAR(s):"
find "$ANDROID_DIR/build/outputs/aar" -name "*.aar" 2>/dev/null | sort
