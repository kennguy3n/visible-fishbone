//! [`AndroidAuthSurface`] — Android Custom Tabs implementation of
//! the `sng-oidc` [`AuthSurface`] contract.
//!
//! The OIDC core hands the surface an authorization [`Url`] and
//! expects back the [`CallbackUrl`] the IdP redirected to. On
//! Android the flow is:
//!
//! 1. launch the URL in a Chrome **Custom Tab**
//!    (`CustomTabsIntent.launchUrl`), and
//! 2. the OS routes the IdP's redirect back to the app via the
//!    intent-filter the host registered for the redirect URI;
//!    the host hands that captured URL to [`AndroidAuthSurface::complete`].
//!
//! Because the redirect is delivered on a *different* call than the
//! one that launched the tab, the surface bridges them with a
//! one-shot channel and a [`timeout`](AndroidAuthSurface::with_timeout):
//! `present_auth_url` launches the tab then awaits the captured URL.
//!
//! The trait contract says the surface MUST NOT inspect / validate
//! the callback's query parameters (`state` / `code` verification is
//! the core's job), so the platform-independent
//! [`interpret_callback`] only distinguishes "user dismissed the
//! tab" (→ [`AuthSurfaceError::Cancelled`]) from a captured URL it
//! parses. The host unit tests cover that mapping without a device.

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use sng_oidc::{AuthSurface, AuthSurfaceError, CallbackUrl};
use tokio::sync::oneshot;
use url::Url;

/// Default wait for the redirect callback before giving up
/// (mirrors the typical interactive-sign-in budget).
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// Interpret the platform's capture result.
///
/// `Some(raw)` is the redirect URL the OS routed back (parsed, not
/// otherwise validated); `None` means the user dismissed the Custom
/// Tab before the IdP redirected, which maps to
/// [`AuthSurfaceError::Cancelled`].
pub fn interpret_callback(captured: Option<&str>) -> Result<CallbackUrl, AuthSurfaceError> {
    match captured {
        Some(raw) => CallbackUrl::parse(raw),
        None => Err(AuthSurfaceError::Cancelled),
    }
}

/// Android Custom Tabs [`AuthSurface`].
pub struct AndroidAuthSurface {
    redirect_uri: String,
    timeout: Duration,
    /// Sender for the in-flight authorization's captured redirect.
    /// `Some(url)` carries the redirect; `None` signals user
    /// cancellation. Held in an `Option` so a completed/forgotten
    /// flow leaves it empty.
    pending: Mutex<Option<oneshot::Sender<Option<String>>>>,
}

impl fmt::Debug for AndroidAuthSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let in_flight = self.pending.lock().is_ok_and(|g| g.is_some());
        f.debug_struct("AndroidAuthSurface")
            .field("redirect_uri", &self.redirect_uri)
            .field("timeout", &self.timeout)
            .field("authorization_in_flight", &in_flight)
            .finish()
    }
}

impl AndroidAuthSurface {
    /// Construct a surface for the app's registered `redirect_uri`,
    /// using the [`DEFAULT_AUTH_TIMEOUT`].
    #[must_use]
    pub fn new(redirect_uri: impl Into<String>) -> Self {
        Self {
            redirect_uri: redirect_uri.into(),
            timeout: DEFAULT_AUTH_TIMEOUT,
            pending: Mutex::new(None),
        }
    }

    /// Construct a surface with an explicit callback timeout.
    #[must_use]
    pub fn with_timeout(redirect_uri: impl Into<String>, timeout: Duration) -> Self {
        Self {
            redirect_uri: redirect_uri.into(),
            timeout,
            pending: Mutex::new(None),
        }
    }

    /// The app's registered redirect URI.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Hand the surface the redirect URL captured by the host's
    /// intent-filter, completing the in-flight `present_auth_url`.
    ///
    /// Pass `None` if the user dismissed the tab. A no-op if no
    /// authorization is in flight.
    pub fn complete(&self, callback_url: Option<String>) {
        if let Ok(mut guard) = self.pending.lock() {
            if let Some(tx) = guard.take() {
                // Receiver gone (timed out / dropped) is fine.
                let _ = tx.send(callback_url);
            }
        }
    }
}

#[async_trait]
impl AuthSurface for AndroidAuthSurface {
    async fn present_auth_url(&self, url: &Url) -> Result<CallbackUrl, AuthSurfaceError> {
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self
                .pending
                .lock()
                .map_err(|_| AuthSurfaceError::Presentation("auth surface lock poisoned".into()))?;
            *guard = Some(tx);
        }

        // Launch the Custom Tab. On the host this is unsupported and
        // returns before we ever await the callback.
        if let Err(e) = imp::launch(url) {
            // Drop the pending sender so a later `complete` is a
            // no-op rather than dangling.
            if let Ok(mut guard) = self.pending.lock() {
                let _ = guard.take();
            }
            return Err(e.into());
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(captured)) => interpret_callback(captured.as_deref()),
            // Sender dropped without delivering — treat as cancel.
            Ok(Err(_)) => Err(AuthSurfaceError::Cancelled),
            Err(_) => {
                if let Ok(mut guard) = self.pending.lock() {
                    let _ = guard.take();
                }
                Err(AuthSurfaceError::Timeout)
            }
        }
    }
}

/// Host (non-Android) fallback: no Custom Tabs to launch.
#[cfg(not(target_os = "android"))]
mod imp {
    use url::Url;

    use crate::error::AndroidPalError;

    pub(super) fn launch(_url: &Url) -> Result<(), AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidAuthSurface::present_auth_url",
        ))
    }
}

/// Android implementation: launch the authorization URL in a Chrome
/// Custom Tab.
#[cfg(target_os = "android")]
mod imp {
    use jni::objects::JValue;
    use url::Url;

    use crate::error::AndroidPalError;
    use crate::jni_bridge::{android_context, with_env};

    pub(super) fn launch(url: &Url) -> Result<(), AndroidPalError> {
        with_env(|env| {
            // new CustomTabsIntent.Builder().build()
            let builder = env
                .new_object(
                    "androidx/browser/customtabs/CustomTabsIntent$Builder",
                    "()V",
                    &[],
                )
                .map_err(|e| AndroidPalError::Jni(format!("CustomTabsIntent.Builder: {e}")))?;
            let intent = env
                .call_method(
                    &builder,
                    "build",
                    "()Landroidx/browser/customtabs/CustomTabsIntent;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Jni(format!("CustomTabsIntent.build: {e}")))?;

            // Uri uri = Uri.parse(url)
            let url_str = env
                .new_string(url.as_str())
                .map_err(|e| AndroidPalError::Jni(format!("new_string(url): {e}")))?;
            let uri = env
                .call_static_method(
                    "android/net/Uri",
                    "parse",
                    "(Ljava/lang/String;)Landroid/net/Uri;",
                    &[JValue::Object(&url_str)],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Jni(format!("Uri.parse: {e}")))?;

            // intent.launchUrl(context, uri)
            let context = android_context();
            env.call_method(
                &intent,
                "launchUrl",
                "(Landroid/content/Context;Landroid/net/Uri;)V",
                &[JValue::Object(&context), JValue::Object(&uri)],
            )
            .map_err(|e| AndroidPalError::Jni(format!("CustomTabsIntent.launchUrl: {e}")))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn interpret_parses_captured_callback() {
        let cb = interpret_callback(Some("com.example.app:/cb?code=abc&state=xyz"))
            .expect("parse callback");
        assert_eq!(cb.code().as_deref(), Some("abc"));
        assert_eq!(cb.state().as_deref(), Some("xyz"));
    }

    #[test]
    fn interpret_none_is_cancelled() {
        let err = interpret_callback(None).expect_err("cancelled");
        assert!(matches!(err, AuthSurfaceError::Cancelled));
    }

    #[test]
    fn interpret_unparseable_is_invalid_callback() {
        let err = interpret_callback(Some("not a url")).expect_err("invalid");
        assert!(matches!(err, AuthSurfaceError::InvalidCallback(_)));
    }

    #[test]
    fn debug_redacts_and_reports_state() {
        let surface = AndroidAuthSurface::new("com.example.app:/cb");
        let rendered = format!("{surface:?}");
        assert!(rendered.contains("redirect_uri"));
        assert!(rendered.contains("authorization_in_flight"));
    }

    #[tokio::test]
    async fn host_present_reports_presentation_error() {
        let surface = AndroidAuthSurface::new("com.example.app:/cb");
        assert_eq!(surface.redirect_uri(), "com.example.app:/cb");
        let url = Url::parse("https://idp.example.com/authorize?client_id=x").expect("url");
        let err = surface.present_auth_url(&url).await.expect_err("host");
        assert!(matches!(err, AuthSurfaceError::Presentation(_)));
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let surface: Arc<dyn AuthSurface> =
            Arc::new(AndroidAuthSurface::new("com.example.app:/cb"));
        let _ = format!("{surface:?}");
    }
}
