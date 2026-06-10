# LLM Inference Validation — Quality Report

_Generated 2026-06-10T15:52:44Z_

Mode: **live inference** — model `qwen2.5:0.5b` at `http://localhost:11434/v1/chat/completions`.

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
| Latency p50 / p95 / p99 | 890 / 1093 / 1093 ms |

## Per-query results

| Question | Kind | Verdict | Mode | ai_gen | valid_json | latency |
|---|---|---|---|---|---|---|
| Can app salesforce.com be reached from device laptop1? | policy_verdict | allow | compiled-bundle | true | true | 753 ms |
| Can app evil.com be reached from device laptop2? | policy_verdict | deny | compiled-bundle | true | true | 823 ms |
| Can app internal.corp be reached from device kiosk9? | policy_verdict | allow | compiled-bundle | true | true | 811 ms |
| Can user alice access app salesforce.com from device laptop1? | policy_verdict | allow | compiled-bundle | true | true | 779 ms |
| show blocked traffic for user alice in the last 24h | blocked_traffic | informational | intent-classified | true | true | 890 ms |
| show blocked traffic for user bob since last week | blocked_traffic | informational | intent-classified | true | true | 805 ms |
| list blocked connections for user carol in the last 7 days | blocked_traffic | informational | intent-classified | true | true | 801 ms |
| report blocked traffic for dave today | blocked_traffic | informational | intent-classified | true | true | 783 ms |
| what changed since last week | change_summary | informational | intent-classified | true | true | 913 ms |
| what has changed since yesterday | change_summary | informational | intent-classified | true | true | 945 ms |
| what changed in the last 7 days | change_summary | informational | intent-classified | true | true | 940 ms |
| what configuration changed since last month | change_summary | informational | intent-classified | true | true | 912 ms |
| compare policy versions | policy_version_compare | informational | intent-classified | true | true | 949 ms |
| compare policy versions 3 and 5 | policy_version_compare | informational | intent-classified | true | true | 856 ms |
| compare policy v2 and v5 | policy_version_compare | informational | intent-classified | true | true | 895 ms |
| diff policy versions 7 and 8 | policy_version_compare | informational | intent-classified | true | true | 1093 ms |
| which devices failed posture in 24h | posture_failure | informational | intent-classified | true | true | 801 ms |
| show devices failing posture checks today | posture_failure | informational | intent-classified | true | true | 952 ms |
| which devices failed posture in the last 7 days | posture_failure | informational | intent-classified | true | true | 849 ms |
| list devices that failed posture since yesterday | posture_failure | informational | intent-classified | true | true | 966 ms |
