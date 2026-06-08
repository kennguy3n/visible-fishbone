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

## Air-gapped image

`Dockerfile.ollama` bakes the model into the image so no runtime egress
is needed:

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
# values.yaml (sng-control)
config:
  AI_LLM_ENDPOINT: "http://ollama:11434/v1/chat/completions"
  AI_LLM_MODEL: "prism-ml/Ternary-Bonsai-8B-gguf"
  AI_LLM_MODEL_FAMILY: "ternary-bonsai"
  AI_LLM_TIMEOUT: "15s"
```

`access-ai-agent` uses the same endpoint via its own
`ACCESS_AI_LLM_ENDPOINT` / `ACCESS_AI_LLM_MODEL_8B` env vars (see the
`fishbone-access` repo).
