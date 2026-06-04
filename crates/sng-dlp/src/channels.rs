//! Endpoint egress channels and the interceptor contract.
//!
//! A *channel* is an on-device path by which content can leave the
//! endpoint or cross a trust boundary. Each channel is hooked by a
//! per-OS backend in `sng-pal` (Windows WMI clipboard listener +
//! USN journal + print spooler hook; macOS NSPasteboard observer +
//! FSEvents + CUPS filter; Linux inotify + udev). Those backends
//! implement [`ChannelInterceptor`]: they surface a stream of
//! [`ContentEvent`]s that the [`crate::engine::DlpEngine`] then
//! classifies and rules on.
//!
//! The contract is intentionally narrow — yield one content event
//! at a time until the source closes — so the same shape works for
//! an edge-triggered OS hook and the deterministic in-memory test
//! double used across the workspace's unit tests.

use crate::classifier::ContentMetadata;
use crate::rules::RuleAction;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// The on-device egress channels DLP inspects.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpChannel {
    /// Clipboard copy/paste to an external (non-allow-listed)
    /// target. Hooked by the WMI clipboard listener (Windows),
    /// NSPasteboard observer (macOS), or the X11 / Wayland
    /// selection bridge (Linux).
    Clipboard,
    /// A write to a watched sensitive directory. Hooked by the USN
    /// journal (Windows), FSEvents (macOS), or inotify (Linux).
    FileWrite,
    /// A document submitted to the print spooler. Hooked by the
    /// print-spooler shim (Windows), a CUPS filter (macOS / Linux).
    Print,
    /// A copy onto removable storage. Hooked by removable-mount
    /// detection (USN / FSEvents / udev) plus a scan of the
    /// copied file.
    UsbTransfer,
    /// A browser file/form upload. Coordinated with the SWG so the
    /// upload body is inspected before it leaves the host.
    BrowserUpload,
}

impl DlpChannel {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clipboard => "clipboard",
            Self::FileWrite => "file_write",
            Self::Print => "print",
            Self::UsbTransfer => "usb_transfer",
            Self::BrowserUpload => "browser_upload",
        }
    }

    /// Every channel, in declaration order. Used by the policy
    /// loader to materialise a default config for channels the
    /// bundle does not mention.
    #[must_use]
    pub const fn all() -> [DlpChannel; 5] {
        [
            Self::Clipboard,
            Self::FileWrite,
            Self::Print,
            Self::UsbTransfer,
            Self::BrowserUpload,
        ]
    }
}

/// Per-channel configuration carried in the policy. A channel that
/// is disabled is skipped entirely (no classification cost); an
/// enabled channel may override the rule-derived action with a
/// channel-wide floor via [`Self::action_override`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Whether DLP inspection runs on this channel at all.
    pub enabled: bool,
    /// Optional channel-wide action floor. When set, a matching
    /// verdict on this channel is escalated to at least this
    /// action even if every matching rule asked for something
    /// weaker. `None` means "use the rule-derived action".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_override: Option<RuleAction>,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action_override: None,
        }
    }
}

/// A single unit of content observed crossing a [`DlpChannel`],
/// produced by a [`ChannelInterceptor`] backend.
///
/// `content` is the raw bytes to inspect. They live only as long as
/// the inspection call; the engine emits **metadata only** and
/// never copies the matched bytes into its verdict (the redaction
/// invariant), so a `ContentEvent` is the single place the raw
/// payload exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentEvent {
    /// The channel that produced the content.
    pub channel: DlpChannel,
    /// The bytes to inspect.
    pub content: Vec<u8>,
    /// Out-of-band context (filename, declared MIME, MIP labels).
    pub metadata: ContentMetadata,
}

impl ContentEvent {
    /// Construct a content event with empty metadata.
    #[must_use]
    pub fn new(channel: DlpChannel, content: Vec<u8>) -> Self {
        Self {
            channel,
            content,
            metadata: ContentMetadata::default(),
        }
    }

    /// Builder-style metadata attachment.
    #[must_use]
    pub fn with_metadata(mut self, metadata: ContentMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Error surfaced by a channel interceptor backend.
#[derive(Debug, Error)]
pub enum ChannelError {
    /// The backend is not available on this OS / build (e.g. the
    /// print-spooler hook on a headless host).
    #[error("channel backend unavailable: {0}")]
    Unavailable(String),
    /// The backend could not initialise its OS hook (driver not
    /// loaded, permission missing, API unavailable).
    #[error("channel init: {0}")]
    Init(String),
    /// The source has been shut down permanently.
    #[error("channel closed")]
    Closed,
}

/// A per-channel interceptor backend. Implemented by `sng-pal` for
/// each OS; the agent drives it by calling [`Self::next_event`]
/// repeatedly until it yields `Ok(None)` (clean close) or an error.
#[async_trait]
pub trait ChannelInterceptor: Send + Sync {
    /// Which channel this interceptor watches.
    fn channel(&self) -> DlpChannel;

    /// Yield the next observed content event, or `None` when the
    /// underlying OS hook has been torn down cleanly.
    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError>;
}

/// Deterministic in-memory interceptor. Used as a test double in
/// every dependent crate (mirrors `sng_pal::traffic::InMemoryCapture`):
/// events are popped FIFO from an `Arc<Mutex<VecDeque>>`.
#[derive(Clone, Debug)]
pub struct InMemoryInterceptor {
    channel: DlpChannel,
    inner: Arc<Mutex<VecDeque<ContentEvent>>>,
}

impl InMemoryInterceptor {
    /// Construct an empty interceptor for `channel`.
    #[must_use]
    pub fn new(channel: DlpChannel) -> Self {
        Self {
            channel,
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Push an event; it appears in [`Self::next_event`] in push
    /// order. The event's own channel is overwritten with this
    /// interceptor's channel so the test double stays consistent.
    pub fn push(&self, mut event: ContentEvent) {
        event.channel = self.channel;
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(event);
    }

    /// Number of queued events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
}

#[async_trait]
impl ChannelInterceptor for InMemoryInterceptor {
    fn channel(&self) -> DlpChannel {
        self.channel
    }

    async fn next_event(&self) -> Result<Option<ContentEvent>, ChannelError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn channel_wire_strings_are_stable() {
        assert_eq!(DlpChannel::Clipboard.as_str(), "clipboard");
        assert_eq!(DlpChannel::FileWrite.as_str(), "file_write");
        assert_eq!(DlpChannel::Print.as_str(), "print");
        assert_eq!(DlpChannel::UsbTransfer.as_str(), "usb_transfer");
        assert_eq!(DlpChannel::BrowserUpload.as_str(), "browser_upload");
        assert_eq!(DlpChannel::all().len(), 5);
    }

    #[test]
    fn channel_roundtrips_through_json() {
        for c in DlpChannel::all() {
            let json = serde_json::to_string(&c).expect("encode");
            let back: DlpChannel = serde_json::from_str(&json).expect("decode");
            assert_eq!(c, back);
        }
    }

    #[test]
    fn channel_config_defaults_to_enabled_no_override() {
        let c = ChannelConfig::default();
        assert!(c.enabled);
        assert_eq!(c.action_override, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_memory_interceptor_is_fifo_and_tags_channel() {
        let i = InMemoryInterceptor::new(DlpChannel::UsbTransfer);
        // Pushed with the "wrong" channel — interceptor must retag.
        i.push(ContentEvent::new(DlpChannel::Clipboard, b"a".to_vec()));
        i.push(ContentEvent::new(DlpChannel::Clipboard, b"b".to_vec()));
        assert_eq!(i.len(), 2);
        assert!(!i.is_empty());

        let first = i.next_event().await.expect("ok").expect("some");
        assert_eq!(first.channel, DlpChannel::UsbTransfer);
        assert_eq!(first.content, b"a");
        let second = i.next_event().await.expect("ok").expect("some");
        assert_eq!(second.content, b"b");
        assert!(i.next_event().await.expect("ok").is_none());
    }
}
