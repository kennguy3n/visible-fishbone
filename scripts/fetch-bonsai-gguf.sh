#!/usr/bin/env bash
# Fetch and cryptographically verify a pinned Ternary-Bonsai-8B GGUF
# artifact from the prism-ml HuggingFace repo.
#
# The ShieldNet AI assistant (internal/service/ai) serves this model over
# an OpenAI-compatible /v1 endpoint. We pin the *exact* GGUF by SHA-256 so
# the air-gapped image bake (deploy/ollama/Dockerfile.llamacpp) and any
# runtime pull are byte-for-byte reproducible and tamper-evident — a
# supply-chain requirement for a security product serving 5K SME tenants.
#
# Default variant is Q2_0, the recommended 2-bit (ternary) quantization:
# 2.03 GiB on disk, ~3 GB resident, runs on a commodity 4-core CPU.
#
# Usage:
#   scripts/fetch-bonsai-gguf.sh                 # Q2_0 -> ./models
#   scripts/fetch-bonsai-gguf.sh --variant Q2_0_g64
#   scripts/fetch-bonsai-gguf.sh --out-dir deploy/ollama/models
#   scripts/fetch-bonsai-gguf.sh --print-sha Q2_0   # print pinned digest
#
# Exit codes: 0 ok/verified, 1 usage error, 2 download failure,
# 3 checksum/size mismatch (treat as tamper / corruption — do NOT use).
set -euo pipefail

# --- Pinned manifest -------------------------------------------------------
# Digests captured from the LFS pointers at prism-ml/Ternary-Bonsai-8B-gguf.
# To rotate: update both the SHA-256 and the byte size together. The size
# check is a cheap fail-fast before hashing 2+ GiB.
HF_REPO="${SNG_LLM_HF_REPO:-prism-ml/Ternary-Bonsai-8B-gguf}"
HF_REVISION="${SNG_LLM_HF_REVISION:-main}"

# variant -> "<filename> <sha256> <size_bytes>"
declare -A MANIFEST=(
  [Q2_0]="Ternary-Bonsai-8B-Q2_0.gguf 3c8d70470a5d97e5a2b9410ddd899cb740116591462626c60cb2fead6448f60b 2182184672"
  [Q2_0_g64]="Ternary-Bonsai-8B-Q2_0_g64.gguf e17b298d84ee78797916ae5c2ecc8211469cc65cccfe3080cd9a9bb503fbc55e 2310125920"
  [PQ2_0]="Ternary-Bonsai-8B-PQ2_0.gguf 1376f942aa90e60f7b570c1d81b3916fea1315ff85aa1c4d19006af68fb4b922 2182184672"
  [F16]="Ternary-Bonsai-8B-F16.gguf a6abfaf896c1e36db825112fc0a18e49adea05eeca1c6b2fba4d785ca7e947ff 16383663200"
)

VARIANT="Q2_0"
OUT_DIR="./models"
RESUME=1
PRINT_SHA=""

die() { echo "error: $*" >&2; exit "${2:-1}"; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  echo
  echo "Variants: ${!MANIFEST[*]}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --variant)   VARIANT="${2:?--variant needs a value}"; shift 2 ;;
    --out-dir)   OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
    --print-sha) PRINT_SHA="${2:-$VARIANT}"; shift 2 || shift ;;
    --no-resume) RESUME=0; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown argument: $1 (try --help)" ;;
  esac
done

[ -n "${MANIFEST[$VARIANT]:-}" ] || die "unknown variant '$VARIANT' (have: ${!MANIFEST[*]})"

read -r FILENAME EXPECT_SHA EXPECT_SIZE <<<"${MANIFEST[$VARIANT]}"

if [ -n "$PRINT_SHA" ]; then
  [ -n "${MANIFEST[$PRINT_SHA]:-}" ] || die "unknown variant '$PRINT_SHA'"
  read -r _f _s _z <<<"${MANIFEST[$PRINT_SHA]}"
  echo "$_s  $_f"
  exit 0
fi

# --- Tool resolution (portable across distros / macOS) ---------------------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else die "need sha256sum or shasum to verify the download"; fi
}
size_of() { wc -c <"$1" | tr -d ' '; }

command -v curl >/dev/null 2>&1 || die "curl is required"

mkdir -p "$OUT_DIR"
DEST="$OUT_DIR/$FILENAME"
URL="https://huggingface.co/$HF_REPO/resolve/$HF_REVISION/$FILENAME"

verify() {
  [ -f "$DEST" ] || return 1
  local sz; sz="$(size_of "$DEST")"
  [ "$sz" = "$EXPECT_SIZE" ] || { echo "size mismatch: got $sz want $EXPECT_SIZE" >&2; return 1; }
  local got; got="$(sha256_of "$DEST")"
  [ "$got" = "$EXPECT_SHA" ] || { echo "sha256 mismatch: got $got want $EXPECT_SHA" >&2; return 1; }
  return 0
}

# Idempotent: a previously verified file is reused untouched.
if verify; then
  echo "ok: $DEST already present and verified (sha256=$EXPECT_SHA)"
  exit 0
fi

echo "Fetching $FILENAME ($VARIANT) from $URL"
echo "  expecting $EXPECT_SIZE bytes, sha256=$EXPECT_SHA"

CURL_OPTS=(--fail --location --retry 5 --retry-delay 5 --retry-connrefused -o "$DEST")
[ "$RESUME" = "1" ] && CURL_OPTS+=(--continue-at -)
# Optional auth for gated/rate-limited mirrors.
[ -n "${HF_TOKEN:-}" ] && CURL_OPTS+=(--header "Authorization: Bearer ${HF_TOKEN}")

if ! curl "${CURL_OPTS[@]}" "$URL"; then
  die "download failed for $URL" 2
fi

if ! verify; then
  echo "VERIFY FAILED — refusing to use a model that does not match the pin." >&2
  echo "Deleting the suspect file; re-run to retry." >&2
  rm -f "$DEST"
  exit 3
fi

echo "verified: $DEST"
echo
echo "Next steps:"
echo "  llama.cpp (Q2_0 needs the prism fork):"
echo "    llama-server -m \"$DEST\" --alias Ternary-Bonsai-8B --host 0.0.0.0 --port 8081 -c 4096"
echo "  air-gapped image bake (context = repo root):"
echo "    docker build -f deploy/ollama/Dockerfile.llamacpp -t sng-bonsai-q2:local ."
