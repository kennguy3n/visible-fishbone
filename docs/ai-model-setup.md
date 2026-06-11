# AI model setup — self-hosted Ternary-Bonsai-8B

The ShieldNet AI assistant (alert summarization, correlation, NL policy
queries, posture reports) talks to any **OpenAI-compatible**
`/v1/chat/completions` endpoint. The recommended deployment is the
self-hosted, quantized
[**Ternary-Bonsai-8B**](https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf)
model running on commodity hardware via Ollama, llama.cpp, or vLLM.

When `AI_LLM_ENDPOINT` is empty the AI service runs in deterministic
**template-only mode** — every feature still works, just without
LLM-polished prose. Security enforcement never depends on the LLM.

## Why self-hosted

| | OpenAI GPT-4o-mini (API) | Ternary-Bonsai-8B (self-hosted) |
|---|---|---|
| Pricing | per-token (~$0.15/1M in, ~$0.60/1M out) | flat infra cost |
| Cost @ 5K tenants¹ | ~$50–200/month and rising with usage | $0 marginal / fixed infra |
| Data residency | leaves your network | stays on-prem |
| Air-gap | not possible | fully supported |

¹ 5K tenants × ~10 AI calls/day × ~500 tokens avg. See
[`cost-model.md`](./cost-model.md) for the detailed breakdown.

## Hardware sizing

| Quantization | Disk | RAM (min / recommended) | Notes |
|---|---|---|---|
| **Q2_0 (2-bit, ternary)** | **2.03 GiB** | **3 GB / 6 GB** | **Recommended for commodity CPU / SME edge.** {-1,0,+1} ternary weights, g128. Needs the prism llama.cpp fork (see below). |
| Q2_0_g64 | 2.15 GiB | 3 GB / 6 GB | Smaller group size (g64): marginally higher fidelity, slightly larger. |
| Q4_K_M | ~4.9 GB | 8 GB / 16 GB | Mainline-Ollama-compatible; higher RAM. |
| GPU (A10G / 24 GB) | — | — | ~10× CPU throughput; for high concurrency. |

The RAM figures are resident set (model + KV-cache at `-c 4096`); add
headroom for concurrency. Q2_0 at ~3 GB resident is what makes a
single-node, **per-tenant-isolated** deployment economical across 5K SME
tenants without GPUs.

The compose `q2` profile caps the container at `${SNG_LLM_MEM_LIMIT:-4g}`,
which leaves ~1 GB headroom over the ~3 GB default footprint. KV-cache scales
with context length, so raise the context and the memory cap **together** —
e.g. `SNG_LLM_CTX=8192 SNG_LLM_MEM_LIMIT=6g docker compose -f
deploy/ollama/docker-compose.yml --profile q2 up -d bonsai-q2` — otherwise a
larger context can OOM-kill the container with no obvious diagnostic.

**Expected inference latency:** ~2–5s for a 512-token response on a
4-core CPU; sub-second on a single A10G. Reference throughput for Q2_0
(llama.cpp, Apple M4 Pro): ~32 tok/s decode on 10 CPU threads, ~76 tok/s
on Metal GPU. This is why the client default timeout (`AI_LLM_TIMEOUT`) is
**15s**, higher than a typical hosted-API client. Completions default to
**512 tokens** (`max_tokens`), which keeps an 8B-class model in its
high-quality regime; callers that need longer structured output (e.g.
policy-graph JSON) request more explicitly.

## Recommended: pinned Q2_0 bundle

The owner-recommended artifact is the **2-bit Q2_0** GGUF
[`Ternary-Bonsai-8B-Q2_0.gguf`](https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf/blob/main/Ternary-Bonsai-8B-Q2_0.gguf).
[`deploy/ollama/`](../deploy/ollama/) ships a turnkey, reproducible,
air-gap-friendly deployment for it.

> **Kernel note:** Q2_0 is a Prism ternary format **not in mainline
> llama.cpp / Ollama** yet, so a stock `ollama/ollama` image cannot load
> it. The supported server is llama.cpp's `llama-server` built from the
> prism fork (`PrismML-Eng/llama.cpp`, pinned in
> [`deploy/ollama/Dockerfile.llamacpp`](../deploy/ollama/Dockerfile.llamacpp)).

**1. Download + verify (SHA-256 pinned, tamper-evident):**

```bash
scripts/fetch-bonsai-gguf.sh --out-dir deploy/ollama/models
# verified sha256 3c8d70470a5d97e5a2b9410ddd899cb740116591462626c60cb2fead6448f60b
```

**2a. Image-bake (air-gapped):** builds the prism fork + bakes the verified
GGUF into the image layer (the build re-verifies the checksum, failing the
build on any mismatch):

```bash
docker build -f deploy/ollama/Dockerfile.llamacpp -t sng-bonsai-q2:local .
docker run --rm -p 127.0.0.1:8081:8081 sng-bonsai-q2:local
```

**2b. Runtime-pull:** fetch + serve on the host (no image build):

```bash
scripts/fetch-bonsai-gguf.sh --out-dir ./models
llama-server -m ./models/Ternary-Bonsai-8B-Q2_0.gguf \
  --alias Ternary-Bonsai-8B --host 0.0.0.0 --port 8081 -c 4096 -ngl 0
```

**2c. Offline image-bake (no HuggingFace egress during build):** for a build
host with no egress to HuggingFace, pre-fetch the GGUF on a connected machine,
stage it under `deploy/ollama/models/`, then build with `SNG_LLM_OFFLINE=1`. The
build skips the model download and only re-verifies the staged file's SHA-256 —
it fails fast (exit 2) if the file is missing, or (exit 3) if it fails
verification, so an absent or tampered artifact never reaches the image:

```bash
# On a connected host (or copy the verified GGUF in by any trusted channel):
scripts/fetch-bonsai-gguf.sh --out-dir deploy/ollama/models

# On the build host — the model is no longer fetched from HuggingFace:
docker build -f deploy/ollama/Dockerfile.llamacpp \
  --build-arg SNG_LLM_OFFLINE=1 -t sng-bonsai-q2:local .
# or via compose: SNG_LLM_OFFLINE=1 docker compose -f deploy/ollama/docker-compose.yml build bonsai-q2
```

`SNG_LLM_OFFLINE=1` removes only the multi-GB model download. Stage 1 still
compiles `llama-server` from the pinned prism fork (a `git fetch`) and pulls the
debian base image + apt packages, so a *fully* air-gapped build also needs those
layers cached (a prior build on the host), pre-built, or served from an internal
mirror. The staged `*.gguf` are gitignored (a tracked `.keep` keeps the
directory so the `COPY` works on a clean checkout) — never commit multi-GB
weights.

Either way the served model name is `Ternary-Bonsai-8B` (the `--alias`),
matching `ai.DefaultModel`, so:

```bash
AI_LLM_ENDPOINT=http://localhost:8081/v1/chat/completions
AI_LLM_MODEL=Ternary-Bonsai-8B
AI_LLM_MODEL_FAMILY=ternary-bonsai
AI_LLM_TIMEOUT=15s
```

### Switching quantizations

[`scripts/fetch-bonsai-gguf.sh`](../scripts/fetch-bonsai-gguf.sh) carries a
pinned manifest (filename + SHA-256 + byte size) for every published
variant. Switch with `--variant`:

| `--variant` | File | Size | When to use |
|---|---|---|---|
| `Q2_0` (default) | `Ternary-Bonsai-8B-Q2_0.gguf` | 2.03 GiB | Commodity CPU; best size/quality. |
| `Q2_0_g64` | `Ternary-Bonsai-8B-Q2_0_g64.gguf` | 2.15 GiB | Slightly higher fidelity. |
| `PQ2_0` | `Ternary-Bonsai-8B-PQ2_0.gguf` | 2.03 GiB | Packed Q2_0 layout. |
| `F16` | `Ternary-Bonsai-8B-F16.gguf` | 16.4 GB | Baseline / re-quantization source. |

```bash
scripts/fetch-bonsai-gguf.sh --variant Q2_0_g64 --out-dir deploy/ollama/models
docker build -f deploy/ollama/Dockerfile.llamacpp \
  --build-arg SNG_LLM_VARIANT=Q2_0_g64 -t sng-bonsai-q2g64:local .
```

Print a pinned digest without downloading: `scripts/fetch-bonsai-gguf.sh
--print-sha Q2_0`.

## Option A — Ollama (easiest)

```bash
ollama pull prism-ml/Ternary-Bonsai-8B-gguf
ollama serve   # serves an OpenAI-compatible API on :11434
```

```bash
AI_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions
AI_LLM_MODEL=prism-ml/Ternary-Bonsai-8B-gguf
AI_LLM_MODEL_FAMILY=ternary-bonsai
AI_LLM_TIMEOUT=15s
```

A ready-to-run compose stack (with the model pre-pulled) and an
air-gapped image build live in [`deploy/ollama/`](../deploy/ollama/).

## Option B — llama.cpp (`llama-server`)

This is the supported server for the pinned **Q2_0** variant. Q2_0 needs
the prism fork (`PrismML-Eng/llama.cpp`); build it once, then:

```bash
# Verified download (see "Switching quantizations" above):
scripts/fetch-bonsai-gguf.sh --out-dir ./models
llama-server -m ./models/Ternary-Bonsai-8B-Q2_0.gguf \
  --alias Ternary-Bonsai-8B --port 8081 --ctx-size 4096 -ngl 0
```

The bundled [`deploy/ollama/Dockerfile.llamacpp`](../deploy/ollama/Dockerfile.llamacpp)
does this for you (pinned fork + baked, verified GGUF).

```bash
AI_LLM_ENDPOINT=http://localhost:8081/v1/chat/completions
AI_LLM_MODEL=Ternary-Bonsai-8B
AI_LLM_MODEL_FAMILY=ternary-bonsai
AI_LLM_TIMEOUT=15s
```

## Option C — vLLM (high throughput / GPU)

```bash
python -m vllm.entrypoints.openai.api_server \
  --model prism-ml/Ternary-Bonsai-8B --port 8000
```

```bash
AI_LLM_ENDPOINT=http://localhost:8000/v1/chat/completions
AI_LLM_MODEL=prism-ml/Ternary-Bonsai-8B
AI_LLM_MODEL_FAMILY=ternary-bonsai
AI_LLM_TIMEOUT=15s
```

## Configuration reference

| Env var | Default | Meaning |
|---|---|---|
| `AI_LLM_ENDPOINT` | `""` | OpenAI-compatible chat-completions URL. Empty ⇒ template-only mode. |
| `AI_LLM_API_KEY` | `""` | Optional bearer token (local servers usually need none). |
| `AI_LLM_MODEL` | `Ternary-Bonsai-8B`² | Served model name sent in each request. |
| `AI_LLM_MODEL_FAMILY` | `auto` | Prompt tuning: `ternary-bonsai`, `openai-compat`, or `auto` (infer from model name). |
| `AI_LLM_TIMEOUT` | `15s` | Per-call HTTP timeout. |

² When `AI_LLM_ENDPOINT` is set but `AI_LLM_MODEL` is empty, the control
plane defaults the model to `Ternary-Bonsai-8B`. Set the value to match
the exact tag your server exposes.

### Prompt tuning (`AI_LLM_MODEL_FAMILY`)

An 8B local model benefits from terser, more structured prompts than a
hosted GPT-class model. The family selects the system prompt:

- `ternary-bonsai` → concise prompt instructing JSON output when asked.
- `openai-compat` → the general-purpose analyst prompt.
- `auto` (default) → infers `ternary-bonsai` when the model name contains
  `bonsai`/`ternary`, otherwise `openai-compat`.

### Reliability

The client retries transient failures (transport errors, HTTP 429, and
5xx) once by default with a 2s exponential backoff — local inference
servers can briefly 503 while loading a model. A cancelled/timed-out
context aborts retries immediately. On persistent failure the AI feature
degrades gracefully to its deterministic template output.
