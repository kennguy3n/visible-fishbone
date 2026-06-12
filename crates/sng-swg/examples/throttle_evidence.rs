//! Throttle-scenario evidence generator.
//!
//! Drives the *real* token-bucket [`sng_swg::RateLimiter`] until it
//! rejects a request, then builds the [`sng_swg::Verdict`] the
//! ext-authz handler would return and serialises both the per-request
//! decision trace and the resulting verdict to JSON. This is the
//! source-of-truth artifact behind the blog's "throttle" scenario:
//! nothing is hand-typed — the numbers come from running the limiter.
//!
//! The wire 429/`Retry-After` mapping shown in the artifact mirrors
//! `ExtAuthzResponse::from_verdict`'s `Action::RateLimit` arm
//! (status 429, `retry_after_secs` copied verbatim), which is
//! asserted by the crate's own unit tests.
//!
//! Run with:
//!   cargo run -p sng-swg --example throttle_evidence -- <out.json>

use sng_swg::{Action, RateLimiter, Verdict};

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "throttle-evidence.json".to_string());

    // A deliberately small bucket so the demo rejects quickly: 5
    // tokens, refilling 1/sec. A burst of 8 back-to-back requests
    // from one principal therefore exhausts the bucket and the
    // limiter starts shedding with a Retry-After.
    let capacity = 5.0_f64;
    let refill_per_sec = 1.0_f64;
    let limiter = RateLimiter::with_system_clock(capacity, refill_per_sec);

    let tenant = "92112770-7c0a-410b-b0f4-09dde70e063a"; // Acme Retail (canonical)
    let principal = "svc-bulk-backup@acme.example";

    let mut trace = Vec::new();
    let mut first_reject: Option<(String, u64)> = None;
    for i in 1..=8u32 {
        let d = limiter.acquire(tenant, principal);
        trace.push(serde_json::json!({
            "request": i,
            "permitted": d.permitted,
            "retry_after_secs": d.retry_after_secs,
            "bucket_key": d.bucket_key,
        }));
        if !d.permitted && first_reject.is_none() {
            first_reject = Some((d.bucket_key.clone(), d.retry_after_secs));
        }
    }

    let (bucket_key, retry_after) = first_reject
        .expect("an 8-request burst against a 5-token bucket must reject at least once");

    // The verdict the ext-authz handler returns on the first shed
    // request — real crate type, real Serialize impl.
    let verdict = Verdict::rate_limit(format!("rate_limit.{bucket_key}"), retry_after);
    assert_eq!(verdict.action, Action::RateLimit);

    let artifact = serde_json::json!({
        "scenario": "throttle",
        "source": "sng-swg::RateLimiter (token bucket) + Verdict::rate_limit",
        "limiter": { "capacity_tokens": capacity, "refill_per_sec": refill_per_sec },
        "burst_trace": trace,
        "verdict": verdict,
        "wire_response": {
            "_comment": "ExtAuthzResponse::from_verdict maps Action::RateLimit -> HTTP 429 with Retry-After copied verbatim",
            "action": "rate_limit",
            "status": 429,
            "reason": verdict.reason,
            "retry_after_secs": verdict.retry_after_secs,
        },
    });

    let json = serde_json::to_string_pretty(&artifact).expect("serialize");
    std::fs::write(&out, json + "\n").expect("write artifact");
    eprintln!("wrote throttle evidence -> {out}");
}
