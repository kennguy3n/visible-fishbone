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

# The workspace `[profile.release]` sets `strip = true`, which strips
# the symbols UniFFI's `generate --library` reads its metadata from
# (a stripped library yields *no* bindings, silently). Override
# `strip` to keep the optimized library while retaining the metadata
# the generator needs. The binding *source* is identical across
# profiles, so debug works too.
if [ "$PROFILE" = "release" ]; then
  BUILD_FLAGS=(--release --config profile.release.strip=false)
  LIB_PATH="target/release/$LIB"
else
  BUILD_FLAGS=()
  LIB_PATH="target/$PROFILE/$LIB"
fi

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
