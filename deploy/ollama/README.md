# Self-hosted LLM (Ternary-Bonsai-8B) via Ollama

This directory provides a turnkey, self-hosted OpenAI-compatible LLM for
the ShieldNet AI assistant. It serves
[Ternary-Bonsai-8B](https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf),
a quantized 8B model that runs on commodity hardware. Both `sng-control`
and `access-ai-agent` (in the `fishbone-access` repo) can point at it.

See [`docs/ai-model-setup.md`](../../docs/ai-model-setup.md) for the full
guide (llama.cpp / vLLM alternatives, hardware sizing, cost comparison,
expected latency).

## Quick start (docker-compose)

```bash
docker compose -f deploy/ollama/docker-compose.yml up -d
# The ollama-pull init container downloads the model on first boot.
```

Then configure the control plane:

```bash
AI_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions
AI_LLM_MODEL=prism-ml/Ternary-Bonsai-8B-gguf
AI_LLM_MODEL_FAMILY=ternary-bonsai
AI_LLM_TIMEOUT=15s
```

> Note: the served model name (`AI_LLM_MODEL`) must match the tag you
> pulled into Ollama. The chart/`.env` default `Ternary-Bonsai-8B` is the
> recommended served name; if you pull the GGUF tag directly, set
> `AI_LLM_MODEL=prism-ml/Ternary-Bonsai-8B-gguf` (or `ollama cp` it to a
> shorter tag).

## Pinned 2-bit (Q2_0) variant — recommended

The owner-recommended artifact is the **Q2_0** (2-bit ternary) GGUF:
[`Ternary-Bonsai-8B-Q2_0.gguf`](https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf/blob/main/Ternary-Bonsai-8B-Q2_0.gguf)
— **2.03 GiB** on disk, ~3 GB resident, runs on a 4-core commodity CPU.

> **Why not stock Ollama for Q2_0?** Q2_0 is a Prism ternary format that
> is **not in mainline llama.cpp / Ollama yet**, so `ollama/ollama` cannot
> load this GGUF. The supported turnkey server is llama.cpp's
> `llama-server` built from the prism fork — provided here as
> [`Dockerfile.llamacpp`](./Dockerfile.llamacpp). The default Ollama
> `pull` path above still works for the registry's default-tag quant.

### 1. Download + verify the exact GGUF

[`scripts/fetch-bonsai-gguf.sh`](../../scripts/fetch-bonsai-gguf.sh) pins
the artifact by **SHA-256** and refuses anything that doesn't match
(supply-chain / tamper safety):

```bash
scripts/fetch-bonsai-gguf.sh --out-dir deploy/ollama/models
# verified: deploy/ollama/models/Ternary-Bonsai-8B-Q2_0.gguf
# sha256 3c8d70470a5d97e5a2b9410ddd899cb740116591462626c60cb2fead6448f60b
```

Switch quantizations with `--variant Q2_0_g64|PQ2_0|F16` (each has its own
pinned digest in the script's manifest).

### 2a. Image-bake (air-gapped, reproducible)

Builds the prism-fork `llama-server` and bakes the verified GGUF into the
final layer, so a fresh container serves the exact weights with no egress.
The build fetches + re-verifies the GGUF itself (no need to pre-download):

```bash
# context = repo root so the verify script is in scope
docker build -f deploy/ollama/Dockerfile.llamacpp -t sng-bonsai-q2:local .
docker run --rm -p 127.0.0.1:8081:8081 sng-bonsai-q2:local
curl localhost:8081/v1/models    # -> "Ternary-Bonsai-8B"
```

Or via compose (opt-in `q2` profile, leaves the Ollama path untouched):

```bash
docker compose -f deploy/ollama/docker-compose.yml --profile q2 up -d bonsai-q2
```

### 2b. Runtime-pull (llama-server, model fetched at start)

```bash
scripts/fetch-bonsai-gguf.sh --out-dir ./models
llama-server -m ./models/Ternary-Bonsai-8B-Q2_0.gguf \
  --alias Ternary-Bonsai-8B --host 0.0.0.0 --port 8081 -c 4096 -ngl 0
```

`--alias Ternary-Bonsai-8B` makes the served name match `ai.DefaultModel`,
so the control-plane default `AI_LLM_MODEL` works unchanged:

```bash
AI_LLM_ENDPOINT=http://localhost:8081/v1/chat/completions
AI_LLM_MODEL=Ternary-Bonsai-8B
AI_LLM_MODEL_FAMILY=ternary-bonsai
AI_LLM_TIMEOUT=15s
```

## Air-gapped Ollama image (default-tag quant)

`Dockerfile.ollama` bakes the Ollama default-tag model into the image so no
runtime egress is needed (note: this is *not* the Q2_0 variant — see above):

```bash
docker build -f deploy/ollama/Dockerfile.ollama \
  --build-arg SNG_LLM_MODEL=prism-ml/Ternary-Bonsai-8B-gguf \
  -t your-registry/sng-ollama-bonsai:8b .
docker push your-registry/sng-ollama-bonsai:8b
```

## Helm

Point the `sng-control` chart at the in-cluster Ollama service by setting
the AI config values (rendered into the ConfigMap as env vars):

```yaml
# values.yaml (sng-control) — Ollama default-tag quant
config:
  AI_LLM_ENDPOINT: "http://ollama:11434/v1/chat/completions"
  AI_LLM_MODEL: "prism-ml/Ternary-Bonsai-8B-gguf"
  AI_LLM_MODEL_FAMILY: "ternary-bonsai"
  AI_LLM_TIMEOUT: "15s"
```

For the pinned **Q2_0** variant, run the `Dockerfile.llamacpp` image as an
in-cluster Deployment/Service (e.g. `bonsai-q2:8081`) and point the chart
at it — the served name is `Ternary-Bonsai-8B` (the `--alias`), matching
the chart's `AI_LLM_MODEL` default, so only the endpoint changes:

```yaml
# values.yaml (sng-control) — pinned Q2_0 via llama-server
config:
  AI_LLM_ENDPOINT: "http://bonsai-q2:8081/v1/chat/completions"
  AI_LLM_MODEL: "Ternary-Bonsai-8B"
  AI_LLM_MODEL_FAMILY: "ternary-bonsai"
  AI_LLM_TIMEOUT: "15s"
```

`access-ai-agent` uses the same endpoint via its own
`ACCESS_AI_LLM_ENDPOINT` / `ACCESS_AI_LLM_MODEL_8B` env vars (see the
`fishbone-access` repo).
