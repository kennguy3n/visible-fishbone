// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! [`IosAuthSurface`] — the iOS [`AuthSurface`] backend.
//!
//! It presents the authorization URL in an `ASWebAuthenticationSession`
//! and resolves with the captured redirect [`CallbackUrl`]. Per the
//! [`AuthSurface`] contract this layer does **not** inspect the
//! `code` / `state` parameters — that is the OIDC core's job; it only
//! drives the browser session and maps its outcome onto
//! [`CallbackUrl`] / [`AuthSurfaceError`].
//!
//! ## iOS control flow
//!
//! `ASWebAuthenticationSession.start()` must run on the main thread and
//! completes asynchronously via a callback. The iOS path therefore:
//! 1. dispatches the session construction + `start()` onto the main
//!    queue (`dispatch2`),
//! 2. bridges the Objective-C completion block (`block2`) onto a
//!    [`tokio::sync::oneshot`] channel, and
//! 3. keeps the session alive in a main-thread-local until the callback
//!    fires (releasing it then to avoid a retain cycle with its own
//!    completion handler).
//!
//! The outcome→result mapping ([`AuthOutcome`]) is pure and host-tested.
//! Only the session lifecycle is `#[cfg(target_os = "ios")]`; the host
//! fallback returns [`AuthSurfaceError::Presentation`].
//!
//! ### Reviewer notes / runtime caveats (verified to compile, not yet
//! exercised on device)
//! * The session uses the app's **key-window** presentation inference.
//!   On iOS 13+ Apple expects an explicit
//!   `ASWebAuthenticationPresentationContextProviding`; the
//!   `objc2-authentication-services` 0.3 binding only exposes that
//!   protocol method on macOS, so when no context can be inferred the
//!   session reports `PresentationContextNotProvided`, which we map to
//!   [`AuthSurfaceError::Presentation`] (never a fake success). Wiring a
//!   custom presentation anchor is the host-app / UniFFI layer's job
//!   (Session 7), which owns the `UIWindow`.
//! * `present_auth_url` must be awaited while a foreground UI exists.

use async_trait::async_trait;
use sng_oidc::{AuthSurface, AuthSurfaceError, CallbackUrl};
use url::Url;

/// iOS [`AuthSurface`] over `ASWebAuthenticationSession`.
#[derive(Debug, Clone)]
pub struct IosAuthSurface {
    /// Custom redirect scheme the app registered (e.g.
    /// `com.shieldnet.sng`). `None` selects universal-link
    /// (`https`) redirect handling.
    callback_scheme: Option<String>,
    /// Whether to request an ephemeral (no shared cookies) session.
    ephemeral: bool,
}

impl IosAuthSurface {
    /// Construct a surface for a custom-scheme redirect (the common
    /// native-app OIDC case).
    #[must_use]
    pub fn new(callback_scheme: impl Into<String>) -> Self {
        Self {
            callback_scheme: Some(callback_scheme.into()),
            ephemeral: false,
        }
    }

    /// Construct a surface for an `https` universal-link redirect (no
    /// custom scheme).
    #[must_use]
    pub fn universal_link() -> Self {
        Self {
            callback_scheme: None,
            ephemeral: false,
        }
    }

    /// Request an ephemeral web session (does not share Safari cookies),
    /// forcing a fresh login.
    #[must_use]
    pub fn with_ephemeral(mut self, ephemeral: bool) -> Self {
        self.ephemeral = ephemeral;
        self
    }

    /// The configured custom redirect scheme, if any.
    #[must_use]
    pub fn callback_scheme(&self) -> Option<&str> {
        self.callback_scheme.as_deref()
    }

    /// Whether an ephemeral session is requested.
    #[must_use]
    pub fn prefers_ephemeral(&self) -> bool {
        self.ephemeral
    }
}

/// The terminal outcome of an `ASWebAuthenticationSession`, lifted out
/// of Objective-C so the mapping onto [`CallbackUrl`] /
/// [`AuthSurfaceError`] can be unit-tested on the host.
///
/// Compiled on iOS (produced by the completion block) and under `test`
/// (host-verified mapping); gated out of the plain Linux library build.
#[cfg(any(target_os = "ios", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthOutcome {
    /// The session delivered a redirect URL (its absolute string form).
    Callback(String),
    /// The user cancelled / dismissed the session.
    Cancelled,
    /// The session failed to present or errored before redirecting.
    Failed(String),
    /// The session reported neither a URL nor an error (should not
    /// happen; treated as a malformed callback).
    Empty,
}

#[cfg(any(target_os = "ios", test))]
impl IosAuthSurface {
    /// Map an [`AuthOutcome`] onto the [`AuthSurface`] result. Parsing /
    /// validation of the callback URL is delegated to
    /// [`CallbackUrl::parse`]; `code` / `state` are intentionally not
    /// inspected here.
    pub(crate) fn map_outcome(outcome: AuthOutcome) -> Result<CallbackUrl, AuthSurfaceError> {
        match outcome {
            AuthOutcome::Callback(raw) => CallbackUrl::parse(&raw),
            AuthOutcome::Cancelled => Err(AuthSurfaceError::Cancelled),
            AuthOutcome::Failed(msg) => Err(AuthSurfaceError::Presentation(msg)),
            AuthOutcome::Empty => Err(AuthSurfaceError::InvalidCallback(
                "session returned neither a callback URL nor an error".to_owned(),
            )),
        }
    }
}

// ---------------------------------------------------------------------
// iOS backend
// ---------------------------------------------------------------------
#[cfg(target_os = "ios")]
mod session {
    use super::AuthOutcome;
    use block2::RcBlock;
    use dispatch2::DispatchQueue;
    use objc2::AllocAnyThread;
    use objc2::rc::Retained;
    use objc2_authentication_services::ASWebAuthenticationSession;
    use objc2_foundation::{NSError, NSString, NSURL};
    use std::cell::RefCell;
    use std::rc::Rc;
    use tokio::sync::oneshot::Sender;

    /// `ASWebAuthenticationSessionErrorCodeCanceledLogin`.
    const CANCELED_LOGIN_CODE: isize = 1;

    thread_local! {
        /// The in-flight session, held only on the main thread so the
        /// system can present it; cleared by its own completion block.
        static ACTIVE: RefCell<Option<Retained<ASWebAuthenticationSession>>> =
            const { RefCell::new(None) };
    }

    /// Translate the completion block's raw `(NSURL?, NSError?)` into an
    /// [`AuthOutcome`].
    ///
    /// # Safety
    /// `url` / `err` are the pointers Objective-C passes to the
    /// completion block: each is either null or a valid, autoreleased
    /// object for the duration of the call. We only read them.
    #[allow(unsafe_code)]
    unsafe fn outcome_from(url: *mut NSURL, err: *mut NSError) -> AuthOutcome {
        // SAFETY (edition 2024 `unsafe_op_in_unsafe_fn`): the pointers are
        // the autoreleased `(NSURL?, NSError?)` Objective-C hands the
        // completion block; each is null or valid for this call and only
        // read here.
        if let Some(url) = unsafe { url.as_ref() } {
            return match url.absoluteString() {
                Some(s) => AuthOutcome::Callback(s.to_string()),
                None => AuthOutcome::Empty,
            };
        }
        if let Some(err) = unsafe { err.as_ref() } {
            if err.code() == CANCELED_LOGIN_CODE {
                return AuthOutcome::Cancelled;
            }
            return AuthOutcome::Failed(err.localizedDescription().to_string());
        }
        AuthOutcome::Empty
    }

    /// Build, configure, and start the session on the main queue,
    /// resolving `tx` with the outcome.
    ///
    /// # Safety
    /// All Objective-C message sends operate on objects constructed here
    /// on the main thread; the completion block pointer is copied by
    /// `init…` per Cocoa convention, so the local `RcBlock` may drop
    /// after construction.
    #[allow(unsafe_code)]
    pub(super) fn present(
        auth_url: String,
        callback_scheme: Option<String>,
        ephemeral: bool,
        tx: Sender<AuthOutcome>,
    ) {
        DispatchQueue::main().exec_async(move || {
            // Shared so both the completion block and the
            // failed-to-start path can resolve the channel exactly once.
            let shared: Rc<RefCell<Option<Sender<AuthOutcome>>>> = Rc::new(RefCell::new(Some(tx)));
            let for_block = Rc::clone(&shared);

            let handler = RcBlock::new(move |url: *mut NSURL, err: *mut NSError| {
                let outcome = unsafe { outcome_from(url, err) };
                if let Some(sender) = for_block.borrow_mut().take() {
                    let _ = sender.send(outcome);
                }
                ACTIVE.with(|active| *active.borrow_mut() = None);
            });

            let Some(nsurl) = NSURL::URLWithString(&NSString::from_str(&auth_url)) else {
                if let Some(sender) = shared.borrow_mut().take() {
                    let _ = sender.send(AuthOutcome::Failed(format!(
                        "authorization URL is not a valid NSURL: {auth_url}"
                    )));
                }
                return;
            };

            let scheme_ns = callback_scheme.as_deref().map(NSString::from_str);
            // The scheme-based initializer is deprecated in favor of the
            // iOS 17.4+ `initWithURL:callback:` API; we deliberately keep
            // it to support the agent's lower minimum deployment target.
            #[allow(deprecated)]
            let session = unsafe {
                ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
                    ASWebAuthenticationSession::alloc(),
                    &nsurl,
                    scheme_ns.as_deref(),
                    (&*handler as *const block2::DynBlock<dyn Fn(*mut NSURL, *mut NSError)>)
                        .cast_mut(),
                )
            };
            unsafe { session.setPrefersEphemeralWebBrowserSession(ephemeral) };

            ACTIVE.with(|active| *active.borrow_mut() = Some(session.clone()));
            let started = unsafe { session.start() };
            if !started {
                if let Some(sender) = shared.borrow_mut().take() {
                    let _ = sender.send(AuthOutcome::Failed(
                        "ASWebAuthenticationSession failed to start (no presentation context?)"
                            .to_owned(),
                    ));
                }
                ACTIVE.with(|active| *active.borrow_mut() = None);
            }
        });
    }
}

#[cfg(target_os = "ios")]
#[async_trait]
impl AuthSurface for IosAuthSurface {
    async fn present_auth_url(&self, url: &Url) -> Result<CallbackUrl, AuthSurfaceError> {
        let (tx, rx) = tokio::sync::oneshot::channel::<AuthOutcome>();
        session::present(
            url.to_string(),
            self.callback_scheme.clone(),
            self.ephemeral,
            tx,
        );
        match rx.await {
            Ok(outcome) => Self::map_outcome(outcome),
            Err(_) => Err(AuthSurfaceError::Presentation(
                "auth session completed without delivering a result".to_owned(),
            )),
        }
    }
}

// ---------------------------------------------------------------------
// Host fallback (Linux CI / desktop dev): typed "unsupported".
// ---------------------------------------------------------------------
#[cfg(not(target_os = "ios"))]
#[async_trait]
impl AuthSurface for IosAuthSurface {
    async fn present_auth_url(&self, _url: &Url) -> Result<CallbackUrl, AuthSurfaceError> {
        Err(AuthSurfaceError::Presentation(
            "ASWebAuthenticationSession is unsupported on this host platform".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn callback_outcome_parses_into_callback_url() {
        let cb = IosAuthSurface::map_outcome(AuthOutcome::Callback(
            "com.shieldnet.sng:/cb?code=abc&state=xyz".to_owned(),
        ))
        .unwrap();
        // The surface does not interpret params, but the parsed URL must
        // carry them through for the core.
        assert_eq!(cb.code().as_deref(), Some("abc"));
        assert_eq!(cb.state().as_deref(), Some("xyz"));
    }

    #[test]
    fn cancelled_outcome_maps_to_cancelled() {
        assert!(matches!(
            IosAuthSurface::map_outcome(AuthOutcome::Cancelled),
            Err(AuthSurfaceError::Cancelled)
        ));
    }

    #[test]
    fn failed_outcome_maps_to_presentation() {
        let err = IosAuthSurface::map_outcome(AuthOutcome::Failed("boom".to_owned())).unwrap_err();
        match err {
            AuthSurfaceError::Presentation(msg) => assert_eq!(msg, "boom"),
            other => panic!("expected Presentation, got {other:?}"),
        }
    }

    #[test]
    fn empty_outcome_maps_to_invalid_callback() {
        assert!(matches!(
            IosAuthSurface::map_outcome(AuthOutcome::Empty),
            Err(AuthSurfaceError::InvalidCallback(_))
        ));
    }

    #[test]
    fn unparseable_callback_maps_to_invalid_callback() {
        assert!(matches!(
            IosAuthSurface::map_outcome(AuthOutcome::Callback("not a url".to_owned())),
            Err(AuthSurfaceError::InvalidCallback(_))
        ));
    }

    #[test]
    fn constructors_capture_configuration() {
        let custom = IosAuthSurface::new("com.shieldnet.sng");
        assert_eq!(custom.callback_scheme(), Some("com.shieldnet.sng"));
        assert!(!custom.prefers_ephemeral());

        let ephemeral = IosAuthSurface::new("scheme").with_ephemeral(true);
        assert!(ephemeral.prefers_ephemeral());

        let ul = IosAuthSurface::universal_link();
        assert_eq!(ul.callback_scheme(), None);
    }

    #[cfg(not(target_os = "ios"))]
    #[tokio::test]
    async fn host_fallback_is_unsupported_not_panic() {
        let surface = IosAuthSurface::new("com.shieldnet.sng");
        let url = Url::parse("https://idp.example.com/authorize?client_id=x").unwrap();
        assert!(matches!(
            surface.present_auth_url(&url).await,
            Err(AuthSurfaceError::Presentation(_))
        ));
    }
}
