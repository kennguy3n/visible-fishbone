#!/usr/bin/env bash
# Generate the Swift + Kotlin UniFFI bindings for `sng-mobile-sdk`.
#
# The foreign-language source (`.swift` / `.kt` + the C header /
# modulemap) is target-independent: it is generated once from a
# compiled `cdylib` via UniFFI's `generate --library` mode, which
# reads the binding metadata embedded in the library by
# `uniffi::setup_scaffolding!()`. Only the *compiled* library that
# ships alongside the bindings is per-target (see the README for the
# `.xcframework` / `.aar` packaging recipes).
#
# Usage:
#   crates/sng-mobile-sdk/bindings/generate.sh [PROFILE] [OUT_DIR]
#     PROFILE  cargo profile to build the cdylib with (default: release)
#     OUT_DIR  directory to write the bindings into
#              (default: crates/sng-mobile-sdk/bindings/generated)
set -euo pipefail

PROFILE="${1:-release}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_DIR="${2:-$REPO_ROOT/crates/sng-mobile-sdk/bindings/generated}"

cd "$REPO_ROOT"

# The crate's cdylib name is `sng_mobile_sdk` (underscored). Resolve
# the host library extension so the script works on Linux and macOS.
case "$(uname -s)" in
  Darwin) LIB="libsng_mobile_sdk.dylib" ;;
  *)      LIB="libsng_mobile_sdk.so" ;;
esac

# Map the requested profile to (a) its cargo build flag, (b) the cargo
# *profile name* used in `--config profile.<name>.…`, and (c) its
# `target/` output sub-directory. Cargo's dev profile is named `dev`
# but emits to `target/debug`; every other profile's directory matches
# its name. The binding *source* is identical across profiles, so any
# profile works.
case "$PROFILE" in
  release)   BUILD_FLAGS=(--release)            ; PROFILE_NAME="release" ; TARGET_DIR="release" ;;
  dev|debug) BUILD_FLAGS=()                      ; PROFILE_NAME="dev"     ; TARGET_DIR="debug"   ;;
  *)         BUILD_FLAGS=(--profile "$PROFILE")  ; PROFILE_NAME="$PROFILE"; TARGET_DIR="$PROFILE" ;;
esac

# A profile with `strip = true` (the workspace sets this on `release`)
# strips the symbols UniFFI's `generate --library` reads its metadata
# from — a stripped library yields *no* bindings, silently. Override
# `strip` for the selected profile so the (optimized) library still
# carries the metadata the generator needs.
BUILD_FLAGS+=(--config "profile.$PROFILE_NAME.strip=false")
LIB_PATH="target/$TARGET_DIR/$LIB"

echo "==> building $LIB ($PROFILE)"
cargo build -p sng-mobile-sdk "${BUILD_FLAGS[@]}"

mkdir -p "$OUT_DIR"

for LANG in swift kotlin; do
  echo "==> generating $LANG bindings into $OUT_DIR"
  cargo run -q -p sng-uniffi-bindgen -- \
    generate --library "$LIB_PATH" --language "$LANG" --out-dir "$OUT_DIR"
done

echo "==> done; generated files:"
find "$OUT_DIR" -type f | sort
