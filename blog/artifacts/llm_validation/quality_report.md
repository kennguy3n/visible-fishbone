# LLM Inference Validation — Quality Report

_Generated 2026-06-18T12:36:24Z_

Mode: **live inference** — model `Ternary-Bonsai-8B` at `http://127.0.0.1:8081/v1/chat/completions`.

Quantization: `Q2_0`. Hardware: 8 vCPU AMD EPYC 7763 (AVX2/FMA/F16C, no AVX-512/VNNI), 31 GiB RAM, CPU-only -ngl 0, cloud dev VM. Build: `9d4f3f7319f2263e7d85ca26d9a013db2cb56655`. 

> Served by llama-server (prism fork b1-d6cea6e, system_info REPACK=1) on the Ternary-Bonsai-8B Q2_0 GGUF; OpenAI-compatible /v1/chat/completions on :8081.

## Summary

| Metric | Value |
|---|---|
| Queries | 20 |
| Classification accuracy | 100.0% |
| Verdict accuracy | 100.0% |
| Verifier pass rate | 100.0% |
| Fallback agreement | 100.0% |
| ai_generated correctness | 100.0% |
| Parse success rate (valid JSON) | 100.0% |
| Raw-parse agreement vs deterministic | 100.0% |
| Latency p50 / p95 / p99 | 9000 / 11083 / 11336 ms |

## Per-query results

| Question | Kind | Verdict | Mode | ai_gen | valid_json | latency |
|---|---|---|---|---|---|---|
| Can app salesforce.com be reached from device laptop1? | policy_verdict | allow | compiled-bundle | true | true | 9791 ms |
| Can app evil.com be reached from device laptop2? | policy_verdict | deny | compiled-bundle | true | true | 9000 ms |
| Can app internal.corp be reached from device kiosk9? | policy_verdict | allow | compiled-bundle | true | true | 9481 ms |
| Can user alice access app salesforce.com from device laptop1? | policy_verdict | allow | compiled-bundle | true | true | 9313 ms |
| show blocked traffic for user alice in the last 24h | blocked_traffic | informational | intent-classified | true | true | 8612 ms |
| show blocked traffic for user bob since last week | blocked_traffic | informational | intent-classified | true | true | 7063 ms |
| list blocked connections for user carol in the last 7 days | blocked_traffic | informational | intent-classified | true | true | 8254 ms |
| report blocked traffic for dave today | blocked_traffic | informational | intent-classified | true | true | 6872 ms |
| what changed since last week | change_summary | informational | intent-classified | true | true | 8843 ms |
| what has changed since yesterday | change_summary | informational | intent-classified | true | true | 7671 ms |
| what changed in the last 7 days | change_summary | informational | intent-classified | true | true | 9011 ms |
| what configuration changed since last month | change_summary | informational | intent-classified | true | true | 8821 ms |
| compare policy versions | policy_version_compare | informational | intent-classified | true | true | 7695 ms |
| compare policy versions 3 and 5 | policy_version_compare | informational | intent-classified | true | true | 8945 ms |
| compare policy v2 and v5 | policy_version_compare | informational | intent-classified | true | true | 9123 ms |
| diff policy versions 7 and 8 | policy_version_compare | informational | intent-classified | true | true | 11083 ms |
| which devices failed posture in 24h | posture_failure | informational | intent-classified | true | true | 9263 ms |
| show devices failing posture checks today | posture_failure | informational | intent-classified | true | true | 10758 ms |
| which devices failed posture in the last 7 days | posture_failure | informational | intent-classified | true | true | 11336 ms |
| list devices that failed posture since yesterday | posture_failure | informational | intent-classified | true | true | 10534 ms |
