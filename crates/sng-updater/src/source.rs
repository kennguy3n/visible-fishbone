//! Manifest source — the abstract surface the orchestrator
//! uses to pull a signed manifest envelope from the control
//! plane.
//!
//! Production deployments back this with `sng-comms`; the
//! in-process test double [`StaticManifestSource`] returns a
//! caller-supplied envelope (or a caller-supplied sequence of
//! envelopes) so the full install state machine is exercisable
//! without standing up an HTTP server in a unit test.
//!
//! Two read shapes are exposed on the trait:
//!
//! * [`ManifestSource::latest`] — pull the latest manifest the
//!   source has for our target, regardless of whether it is the
//!   same one we already saw. The orchestrator's periodic
//!   poller drives this.
//! * [`ManifestSource::next_after`] — pull a manifest strictly
//!   newer than the supplied pin, if one exists. The control
//!   plane's push-notification path drives this.
//!
//! Both methods return `Option<SignedManifest>` rather than
//! `Result<Option<...>>` so a "no manifest available yet" answer
//! is distinct from a transport-level failure; the latter is
//! surfaced via the `SourceError` taxonomy.

use crate::manifest::{ImageVersion, SignedManifest, UpdateTarget};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use thiserror::Error;

/// Errors a manifest source may surface. Distinct from
/// [`crate::error::UpdaterError`] so transport-level failures
/// (DNS, TLS, HTTP non-2xx) stay bucketed separately from the
/// verifier's manifest-shaped failures.
#[derive(Debug, Error)]
pub enum SourceError {
    /// Transport-level failure (network I/O, HTTP non-2xx). The
    /// orchestrator's retry policy decides whether to back off
    /// and retry.
    #[error("transport: {0}")]
    Transport(String),
    /// The source rejected our request — typically because the
    /// agent's identity is not authorised to pull manifests for
    /// the requested target.
    #[error("rejected: {0}")]
    Rejected(String),
}

/// Trait implemented by every manifest source. The trait is
/// async because the production implementation does network
/// I/O; the in-process [`StaticManifestSource`] is implemented
/// with a no-op await so unit tests run without a real
/// executor.
#[async_trait]
pub trait ManifestSource: Send + Sync {
    /// Pull the latest manifest the source has for the given
    /// target. Returns `Ok(None)` if the source has no manifest
    /// (e.g. the appliance is brand new and there is no current
    /// release).
    async fn latest(&self, target: UpdateTarget) -> Result<Option<SignedManifest>, SourceError>;

    /// Pull a manifest strictly newer than the supplied pin,
    /// if one exists. Used on the push-notification path:
    /// "control plane says version > pin is available, fetch
    /// it". `pin` is the version of the currently-committed
    /// image; on cold start callers pass `None`.
    async fn next_after(
        &self,
        target: UpdateTarget,
        pin: Option<ImageVersion>,
    ) -> Result<Option<SignedManifest>, SourceError>;
}

/// In-process manifest source for testing. Holds a fixed
/// envelope (or a sequence of envelopes pulled in FIFO order)
/// and replies to every `latest` / `next_after` call from the
/// queue. Empty queue → `None`.
///
/// The struct is intentionally not generic over the envelope —
/// callers can mutate the queue freely via
/// [`Self::push`] / [`Self::push_many`] so test cases that need
/// "first pull returns A, second pull returns B" can build
/// that sequence without subclassing.
#[derive(Debug, Default)]
pub struct StaticManifestSource {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    queue: Mutex<VecDeque<SignedManifest>>,
    /// Optional transport failure to surface on every call.
    /// Lets tests assert the orchestrator's retry behaviour on
    /// a soft-fail source without mocking network I/O.
    fail_with: Mutex<Option<String>>,
    /// Count of `latest()` calls served — exposed via
    /// [`Self::latest_call_count`] so periodic-poll tests can
    /// assert the orchestrator polled exactly N times.
    latest_calls: Mutex<u64>,
    /// Count of `next_after()` calls served.
    next_after_calls: Mutex<u64>,
}

impl StaticManifestSource {
    /// Construct an empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a source pre-populated with a single envelope.
    /// Convenience for the common single-pull test case.
    #[must_use]
    pub fn with_envelope(envelope: SignedManifest) -> Self {
        let s = Self::new();
        s.push(envelope);
        s
    }

    /// Push one envelope onto the back of the queue.
    pub fn push(&self, envelope: SignedManifest) {
        self.inner.queue.lock().push_back(envelope);
    }

    /// Push many envelopes onto the back of the queue, in
    /// order. Equivalent to `for e in iter { src.push(e) }`.
    pub fn push_many<I: IntoIterator<Item = SignedManifest>>(&self, iter: I) {
        let mut g = self.inner.queue.lock();
        for e in iter {
            g.push_back(e);
        }
    }

    /// Replace the queue wholesale. Useful for "reset between
    /// scenarios" patterns.
    pub fn replace_queue<I: IntoIterator<Item = SignedManifest>>(&self, iter: I) {
        let mut g = self.inner.queue.lock();
        g.clear();
        for e in iter {
            g.push_back(e);
        }
    }

    /// Force every subsequent call to return
    /// `Err(SourceError::Transport(msg))`. Pass `None` to
    /// clear the override.
    pub fn force_failure(&self, msg: Option<String>) {
        *self.inner.fail_with.lock() = msg;
    }

    /// Total number of [`ManifestSource::latest`] calls served.
    pub fn latest_call_count(&self) -> u64 {
        *self.inner.latest_calls.lock()
    }

    /// Total number of [`ManifestSource::next_after`] calls
    /// served.
    pub fn next_after_call_count(&self) -> u64 {
        *self.inner.next_after_calls.lock()
    }

    /// Current queue depth (used by tests to assert "the
    /// orchestrator consumed exactly the manifest we pushed").
    pub fn queue_depth(&self) -> usize {
        self.inner.queue.lock().len()
    }

    /// Cheap shareable handle. The orchestrator holds an
    /// `Arc<dyn ManifestSource>`, and tests want to mutate the
    /// queue alongside; cloning the handle gives both views
    /// onto the same backing inner state.
    #[must_use]
    pub fn handle(&self) -> Arc<Self> {
        // Construct a separate `Self` over the SAME inner —
        // this is what makes test-code mutation visible to the
        // orchestrator-side `dyn ManifestSource` reader.
        Arc::new(Self {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[async_trait]
impl ManifestSource for StaticManifestSource {
    async fn latest(&self, _target: UpdateTarget) -> Result<Option<SignedManifest>, SourceError> {
        *self.inner.latest_calls.lock() += 1;
        if let Some(msg) = self.inner.fail_with.lock().clone() {
            return Err(SourceError::Transport(msg));
        }
        Ok(self.inner.queue.lock().pop_front())
    }

    async fn next_after(
        &self,
        _target: UpdateTarget,
        _pin: Option<ImageVersion>,
    ) -> Result<Option<SignedManifest>, SourceError> {
        *self.inner.next_after_calls.lock() += 1;
        if let Some(msg) = self.inner.fail_with.lock().clone() {
            return Err(SourceError::Transport(msg));
        }
        Ok(self.inner.queue.lock().pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ImageHash, ManifestSignature, ManifestSigningKeyId, ReleaseChannel, UpdateManifest,
    };
    use pretty_assertions::assert_eq;
    use url::Url;

    fn fixture_envelope(version: ImageVersion) -> SignedManifest {
        let mfst = UpdateManifest {
            schema_version: 1,
            target: UpdateTarget::Edge,
            channel: ReleaseChannel::Stable,
            version,
            image_sha256: ImageHash::new([0_u8; 32]),
            image_size_bytes: 1,
            image_url: Url::parse("https://x.invalid/y").expect("url"),
            release_notes: String::new(),
            signed_at: chrono::Utc::now(),
        };
        SignedManifest::compose(
            &mfst,
            ManifestSignature::new([0_u8; 64]),
            ManifestSigningKeyId::new("k").expect("id"),
        )
        .expect("compose")
    }

    #[tokio::test]
    async fn empty_queue_returns_none() {
        let src = StaticManifestSource::new();
        assert!(src.latest(UpdateTarget::Edge).await.expect("ok").is_none());
        assert!(
            src.next_after(UpdateTarget::Edge, None)
                .await
                .expect("ok")
                .is_none()
        );
        // Call counters still tick — tests rely on this for
        // assertions like "the orchestrator polled twice."
        assert_eq!(src.latest_call_count(), 1);
        assert_eq!(src.next_after_call_count(), 1);
    }

    #[tokio::test]
    async fn pushed_envelope_is_returned_then_drained() {
        let env = fixture_envelope(ImageVersion::new(1, 0, 0));
        let src = StaticManifestSource::with_envelope(env.clone());
        let got = src.latest(UpdateTarget::Edge).await.expect("ok");
        assert_eq!(got, Some(env));
        // Drained — second call returns None.
        assert!(src.latest(UpdateTarget::Edge).await.expect("ok").is_none());
        assert_eq!(src.queue_depth(), 0);
    }

    #[tokio::test]
    async fn push_many_returns_in_fifo_order() {
        let a = fixture_envelope(ImageVersion::new(1, 0, 0));
        let b = fixture_envelope(ImageVersion::new(2, 0, 0));
        let c = fixture_envelope(ImageVersion::new(3, 0, 0));
        let src = StaticManifestSource::new();
        src.push_many([a.clone(), b.clone(), c.clone()]);
        assert_eq!(src.queue_depth(), 3);
        assert_eq!(src.latest(UpdateTarget::Edge).await.expect("ok"), Some(a));
        assert_eq!(src.latest(UpdateTarget::Edge).await.expect("ok"), Some(b));
        assert_eq!(src.latest(UpdateTarget::Edge).await.expect("ok"), Some(c));
    }

    #[tokio::test]
    async fn force_failure_surfaces_on_every_call() {
        let src = StaticManifestSource::with_envelope(fixture_envelope(ImageVersion::new(1, 0, 0)));
        src.force_failure(Some("dns down".into()));
        let err = src.latest(UpdateTarget::Edge).await.expect_err("err");
        assert!(matches!(err, SourceError::Transport(msg) if msg == "dns down"));
        let err2 = src
            .next_after(UpdateTarget::Edge, None)
            .await
            .expect_err("err");
        assert!(matches!(err2, SourceError::Transport(_)));
        // Clearing restores normal behaviour and the queue
        // entry is still pending.
        src.force_failure(None);
        assert!(src.latest(UpdateTarget::Edge).await.expect("ok").is_some());
    }

    #[tokio::test]
    async fn handle_shares_state_with_owner() {
        let owner = StaticManifestSource::new();
        let handle = owner.handle();
        owner.push(fixture_envelope(ImageVersion::new(9, 9, 9)));
        // The clone reader sees the owner-side mutation.
        let got = handle.latest(UpdateTarget::Edge).await.expect("ok");
        assert!(got.is_some());
        assert_eq!(owner.queue_depth(), 0);
    }

    #[tokio::test]
    async fn replace_queue_clears_pending_entries() {
        let src = StaticManifestSource::with_envelope(fixture_envelope(ImageVersion::new(1, 0, 0)));
        assert_eq!(src.queue_depth(), 1);
        src.replace_queue([fixture_envelope(ImageVersion::new(2, 0, 0))]);
        assert_eq!(src.queue_depth(), 1);
        let got = src
            .latest(UpdateTarget::Edge)
            .await
            .expect("ok")
            .expect("some");
        let decoded: UpdateManifest = rmp_serde::from_slice(&got.body).expect("decode");
        assert_eq!(decoded.version, ImageVersion::new(2, 0, 0));
    }
}
