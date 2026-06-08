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

| Quantization | RAM (min / recommended) | Notes |
|---|---|---|
| Q4_K_M | 8 GB / 16 GB | Best size/quality trade-off; default. |
| Q5_K_M | 12 GB / 24 GB | Slightly higher quality, more RAM. |
| GPU (A10G / 24 GB) | — | ~10× CPU throughput; for high concurrency. |

**Expected inference latency:** ~2–5s for a 512-token response on a
4-core CPU; sub-second on a single A10G. This is why the client default
timeout (`AI_LLM_TIMEOUT`) is **15s**, higher than a typical hosted-API
client. Completions default to **512 tokens** (`max_tokens`), which keeps
an 8B-class model in its high-quality regime; callers that need longer
structured output (e.g. policy-graph JSON) request more explicitly.

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

```bash
# Download the GGUF (Q4_K_M) from the HuggingFace repo, then:
llama-server -m Ternary-Bonsai-8B.Q4_K_M.gguf --port 8081 --ctx-size 8192
```

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
