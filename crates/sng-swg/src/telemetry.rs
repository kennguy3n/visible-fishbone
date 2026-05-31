//! SWG → telemetry pipeline glue.
//!
//! The handler emits one [`VerdictEvent`] per request decision
//! and a [`SwgEventSink`] carries the records into the workspace
//! telemetry pipeline. Records are normalised onto
//! [`sng_core::events::HttpEvent`] so the downstream consumer
//! sees the same shape an HTTP-class event has from any other
//! source — the wire envelope schema does not grow a SWG-only
//! variant for what is fundamentally a per-request HTTP record.
//!
//! Events flow through the pipeline via [`SwgEventSource`], an
//! [`sng_telemetry::EventSource`] implementation, the same
//! pattern [`sng_ips::telemetry::IpsEventSource`] uses for
//! Suricata alerts.

use async_trait::async_trait;
use sng_core::envelope::Verdict;
use sng_core::events::HttpEvent;
use sng_telemetry::source::{EventSource, TelemetryEvent};
use tokio::sync::mpsc;

use crate::verdict::{Action, RequestContext, Verdict as SwgVerdict};

/// A single SWG verdict event. Built by the handler from the
/// request context + verdict and pushed through the channel into
/// the telemetry pipeline.
#[derive(Clone, Debug, PartialEq)]
pub struct VerdictEvent {
    /// Tenant the request was issued under.
    pub tenant_id: String,
    /// Principal id (device / user / service account).
    pub principal_id: String,
    /// Normalised HTTP record forwarded into the wire envelope.
    pub http: HttpEvent,
    /// The SWG verdict in its native form. Kept alongside the
    /// HttpEvent because the wire HttpEvent.verdict folds onto
    /// the shared `Verdict` enum and loses the SWG-specific
    /// distinction between `bypass` and `allow`. The telemetry
    /// consumer that needs the SWG-specific detail reads
    /// `swg_verdict`; the consumer that only needs the shared
    /// enum reads `http.verdict`.
    pub swg_verdict: SwgVerdict,
}

impl VerdictEvent {
    /// Build a verdict event from the request context and
    /// the verdict. Performs the wire-format mapping
    /// (Action → Verdict) once so the channel sink does not have
    /// to repeat it.
    #[must_use]
    pub fn from_context(ctx: &RequestContext, verdict: SwgVerdict) -> Self {
        let url = format!("{}://{}{}", ctx.scheme, ctx.host, ctx.path);
        let http = HttpEvent {
            method: ctx.method.clone(),
            url,
            host: ctx.host.clone(),
            // Status code comes from Envoy on the response side;
            // the SWG only knows what *it* would respond. For a
            // request-side verdict the field is zero so the
            // downstream consumer can distinguish "not yet
            // observed on wire" from a real upstream 200.
            status_code: 0,
            verdict: map_action_to_verdict(verdict.action),
            tls_version: None,
            sni: ctx.sni.clone(),
            content_type: None,
            bytes: None,
        };
        Self {
            tenant_id: ctx.tenant_id.clone(),
            principal_id: ctx.principal_id.clone(),
            http,
            swg_verdict: verdict,
        }
    }
}

fn map_action_to_verdict(a: Action) -> Verdict {
    match a {
        // Bypass folds onto Allow on the shared envelope because
        // the per-request fate on the wire is "request completed
        // upstream". The SWG-specific distinction lives on
        // VerdictEvent.swg_verdict.
        Action::Allow | Action::Bypass => Verdict::Allow,
        // Both outright Deny and Deny-by-rate-limit fold onto
        // Verdict::Deny on the shared envelope because the
        // request did NOT reach the upstream. The SWG-specific
        // distinction (e.g. Retry-After) lives on the
        // accompanying VerdictEvent.swg_verdict context.
        Action::Deny | Action::RateLimit => Verdict::Deny,
    }
}

/// Producer half. Held by the manager / handler; pushes one
/// VerdictEvent per request decision.
#[derive(Clone, Debug)]
pub struct SwgEventSink {
    tx: mpsc::Sender<VerdictEvent>,
}

impl SwgEventSink {
    /// Send an event without blocking. Returns the event back if
    /// the channel is full or closed so the caller can decide
    /// (the handler logs + drops; a high-volume scenario means
    /// the telemetry pipeline is the bottleneck and dropping is
    /// strictly better than blocking the per-request hot path).
    pub fn try_send(&self, ev: VerdictEvent) -> Result<(), VerdictEvent> {
        match self.tx.try_send(ev) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(ev) | mpsc::error::TrySendError::Closed(ev)) => {
                Err(ev)
            }
        }
    }

    /// Async send. Back-pressure blocks; only fails on permanent
    /// channel closure.
    pub async fn send(&self, ev: VerdictEvent) -> Result<(), VerdictEvent> {
        self.tx.send(ev).await.map_err(|e| e.0)
    }

    /// Approximate remaining channel capacity. The manager
    /// surfaces this on the health report so an operator can
    /// see when the SWG is back-pressured.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

/// Consumer half. Wired into the telemetry pipeline as one of
/// many [`EventSource`]s. The pipeline normalises the inner
/// HttpEvent onto the wire envelope.
#[derive(Debug)]
pub struct SwgEventSource {
    rx: mpsc::Receiver<VerdictEvent>,
}

impl SwgEventSource {
    /// Build a `(sink, source)` pair with the given channel
    /// capacity. Production default is `1024` — generous enough
    /// for a burst in front of the telemetry consumer, small
    /// enough that one runaway tenant can't pin a lot of memory.
    #[must_use]
    pub fn channel(capacity: usize) -> (SwgEventSink, Self) {
        let (tx, rx) = mpsc::channel(capacity);
        (SwgEventSink { tx }, Self { rx })
    }
}

#[async_trait]
impl EventSource for SwgEventSource {
    async fn recv(&mut self) -> Option<TelemetryEvent> {
        // Lift VerdictEvent → HttpEvent and drop the
        // swg-specific detail. Downstream telemetry consumers
        // can re-derive the SWG distinction from the verdict +
        // reason fields on the HttpEvent if they need it.
        self.rx.recv().await.map(|v| TelemetryEvent::Http(v.http))
    }
}

/// Trait the manager threads through the handler so the test
/// suite can swap a recording emitter in. The production wiring
/// uses [`SwgEventSink`] directly; the trait keeps the handler
/// from needing a recorder type-parameter.
pub trait TelemetryEmitter: Send + Sync + std::fmt::Debug {
    /// Emit one verdict event. Implementations may drop on
    /// back-pressure (a per-request hot path cannot block on
    /// telemetry).
    fn emit(&self, event: VerdictEvent);
}

impl TelemetryEmitter for SwgEventSink {
    fn emit(&self, event: VerdictEvent) {
        // Drop on back-pressure rather than block the
        // per-request handler. The drop is logged but the
        // handler still returns its verdict to Envoy.
        if self.try_send(event).is_err() {
            tracing::warn!("telemetry channel full / closed — verdict event dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    fn sample_ctx() -> RequestContext {
        RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "get".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            path: "/path".into(),
            sni: Some("example.com".into()),
            file_hash: None,
        }
    }

    #[test]
    fn verdict_event_normalises_request_context_into_http_event() {
        let ctx = sample_ctx();
        let v = SwgVerdict::allow_categorized("business.saas");
        let ev = VerdictEvent::from_context(&ctx, v.clone());
        assert_eq!(ev.tenant_id, "tenant-1");
        assert_eq!(ev.principal_id, "device-42");
        assert_eq!(ev.http.method, "get");
        assert_eq!(ev.http.host, "example.com");
        assert_eq!(ev.http.url, "https://example.com/path");
        assert_eq!(ev.http.verdict, Verdict::Allow);
        assert_eq!(ev.http.sni.as_deref(), Some("example.com"));
        assert_eq!(ev.swg_verdict, v);
    }

    #[test]
    fn bypass_action_folds_onto_allow_in_wire_envelope() {
        // The shared Verdict enum has no Bypass variant; the SWG
        // surfaces the distinction on swg_verdict but the
        // pipeline's `verdict` field must be Allow so the
        // downstream consumer counting "allowed requests" sees
        // bypassed flows.
        let ctx = sample_ctx();
        let v = SwgVerdict::bypass("bypass.tls.healthcare");
        let ev = VerdictEvent::from_context(&ctx, v.clone());
        assert_eq!(ev.http.verdict, Verdict::Allow);
        assert_eq!(ev.swg_verdict, v);
    }

    #[test]
    fn rate_limit_action_folds_onto_deny() {
        let ctx = sample_ctx();
        let v = SwgVerdict::rate_limit("rate_limit.tenant", 60);
        let ev = VerdictEvent::from_context(&ctx, v);
        assert_eq!(ev.http.verdict, Verdict::Deny);
    }

    #[test]
    fn deny_action_folds_onto_deny() {
        let ctx = sample_ctx();
        let v = SwgVerdict::deny("deny.category.gambling");
        let ev = VerdictEvent::from_context(&ctx, v);
        assert_eq!(ev.http.verdict, Verdict::Deny);
    }

    #[tokio::test]
    async fn channel_delivers_events_through_event_source_trait() {
        let (sink, mut source) = SwgEventSource::channel(4);
        let ctx = sample_ctx();
        sink.send(VerdictEvent::from_context(
            &ctx,
            SwgVerdict::allow_uncategorized(),
        ))
        .await
        .unwrap();
        drop(sink);
        let lifted = source.recv().await.expect("event");
        match lifted {
            TelemetryEvent::Http(h) => assert_eq!(h.url, "https://example.com/path"),
            other => panic!("expected Http, got {other:?}"),
        }
        // Channel drained — recv returns None.
        assert!(source.recv().await.is_none());
    }

    #[test]
    fn sink_try_send_returns_event_on_closed_channel() {
        // The handler depends on this — when the consumer is
        // gone the handler can choose to log + drop without
        // having to introspect the channel.
        let (sink, source) = SwgEventSource::channel(1);
        drop(source);
        let ctx = sample_ctx();
        let res = sink.try_send(VerdictEvent::from_context(
            &ctx,
            SwgVerdict::allow_uncategorized(),
        ));
        assert!(res.is_err());
    }

    #[derive(Debug, Default)]
    struct RecordingEmitter {
        events: Mutex<Vec<VerdictEvent>>,
    }

    impl TelemetryEmitter for RecordingEmitter {
        fn emit(&self, event: VerdictEvent) {
            self.events.lock().push(event);
        }
    }

    #[test]
    fn telemetry_emitter_trait_supports_test_doubles() {
        let rec = Arc::new(RecordingEmitter::default());
        let ctx = sample_ctx();
        rec.emit(VerdictEvent::from_context(&ctx, SwgVerdict::deny("x")));
        rec.emit(VerdictEvent::from_context(
            &ctx,
            SwgVerdict::allow_uncategorized(),
        ));
        let events = rec.events.lock();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].http.verdict, Verdict::Deny);
        assert_eq!(events[1].http.verdict, Verdict::Allow);
    }
}
