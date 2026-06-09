#!/usr/bin/env bash
# Build the `sng_mobile_sdkFFI.xcframework` and lay out the
# `ShieldNetMobile` Swift Package so it resolves locally / in CI.
#
# Pipeline:
#   1. Regenerate the UniFFI bindings (delegates to the repo's
#      bindings/generate.sh) so the Swift surface + C header + module
#      map match the current crate.
#   2. Cross-compile the crate's `staticlib` for the iOS device and
#      simulator targets, `lipo`-fusing the two simulator archs into a
#      single fat archive.
#   3. Assemble an `.xcframework` from the device + simulator archives
#      plus a headers directory carrying the generated C header and a
#      `module.modulemap` (so the FFI module is importable as
#      `sng_mobile_sdkFFI`).
#   4. Copy the generated `sng_mobile_sdk.swift` into the package's
#      `Sources/ShieldNetMobile/`.
#
# The XCFramework and the copied Swift are git-ignored build outputs.
#
# Usage:
#   crates/sng-mobile-sdk/apple/scripts/build-xcframework.sh [PROFILE]
#     PROFILE  cargo profile to build with (default: release)
#
# Requires a macOS host with Xcode (`xcodebuild`, `lipo`) and the Rust
# Apple targets; it refuses to run elsewhere rather than emit a
# half-built framework.
set -euo pipefail

PROFILE="${1:-release}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$APPLE_DIR/../../.." && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: the iOS XCFramework can only be built on a macOS host" \
       "(needs xcodebuild + lipo); run this in the macOS CI job." >&2
  exit 1
fi

# Device + simulator iOS targets. The simulator slice fuses arm64
# (Apple-silicon Macs) and x86_64 (Intel Macs) so one framework slice
# covers every simulator host.
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")

# Map the cargo profile to its `target/<dir>/` output directory.
case "$PROFILE" in
  release)   BUILD_FLAGS=(--release)           ; TARGET_DIR="release" ;;
  dev|debug) BUILD_FLAGS=()                     ; TARGET_DIR="debug"   ;;
  *)         BUILD_FLAGS=(--profile "$PROFILE") ; TARGET_DIR="$PROFILE" ;;
esac
# `[profile.release] strip = true` would strip the exported C ABI
# symbols the static archive must keep for the app to link; override
# it so the `staticlib` retains them (the final app link dead-strips).
PROFILE_NAME="$PROFILE"
[[ "$PROFILE" == "debug" ]] && PROFILE_NAME="dev"
BUILD_FLAGS+=(--config "profile.$PROFILE_NAME.strip=false")

LIB_BASENAME="libsng_mobile_sdk.a"
GENERATED_DIR="$REPO_ROOT/crates/sng-mobile-sdk/bindings/generated"
BUILD_OUT="$REPO_ROOT/target/apple"
XCFRAMEWORK_OUT="$APPLE_DIR/Frameworks/sng_mobile_sdkFFI.xcframework"
SWIFT_DEST="$APPLE_DIR/Sources/ShieldNetMobile/sng_mobile_sdk.swift"

cd "$REPO_ROOT"

echo "==> regenerating UniFFI bindings"
"$REPO_ROOT/crates/sng-mobile-sdk/bindings/generate.sh" "$PROFILE" "$GENERATED_DIR"

echo "==> ensuring Rust Apple targets are installed"
rustup target add "$DEVICE_TARGET" "${SIM_TARGETS[@]}"

echo "==> building staticlib for device + simulator targets"
for T in "$DEVICE_TARGET" "${SIM_TARGETS[@]}"; do
  cargo build -p sng-mobile-sdk "${BUILD_FLAGS[@]}" --target "$T"
done

echo "==> fusing simulator archs with lipo"
mkdir -p "$BUILD_OUT"
SIM_LIB="$BUILD_OUT/$LIB_BASENAME"
SIM_INPUTS=()
for T in "${SIM_TARGETS[@]}"; do
  SIM_INPUTS+=("target/$T/$TARGET_DIR/$LIB_BASENAME")
done
lipo -create "${SIM_INPUTS[@]}" -output "$SIM_LIB"

echo "==> staging FFI headers + module map"
HEADERS_DIR="$BUILD_OUT/Headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR"
cp "$GENERATED_DIR/sng_mobile_sdkFFI.h" "$HEADERS_DIR/"
# `xcodebuild -create-xcframework -headers` resolves a module from a
# file literally named `module.modulemap`; the generator emits
# `sng_mobile_sdkFFI.modulemap`, so copy it under the expected name.
cp "$GENERATED_DIR/sng_mobile_sdkFFI.modulemap" "$HEADERS_DIR/module.modulemap"

echo "==> assembling $XCFRAMEWORK_OUT"
rm -rf "$XCFRAMEWORK_OUT"
mkdir -p "$(dirname "$XCFRAMEWORK_OUT")"
xcodebuild -create-xcframework \
  -library "target/$DEVICE_TARGET/$TARGET_DIR/$LIB_BASENAME" -headers "$HEADERS_DIR" \
  -library "$SIM_LIB" -headers "$HEADERS_DIR" \
  -output "$XCFRAMEWORK_OUT"

echo "==> copying generated Swift into the package"
cp "$GENERATED_DIR/sng_mobile_sdk.swift" "$SWIFT_DEST"

echo "==> done"
echo "    xcframework: $XCFRAMEWORK_OUT"
echo "    swift:       $SWIFT_DEST"
