//! JNI bootstrap — how the Android PAL reaches the host app's JVM.
//!
//! This module is compiled **only** on `target_os = "android"`; it
//! is the single place the crate touches a raw pointer. The
//! workspace lint is `unsafe_code = "deny"` (not `forbid`) precisely
//! so a leaf module that must cross an FFI boundary can lift the
//! ban locally with a documented rationale (see `sng-pal`'s
//! `sysinfo` sysctl wrapper for the same pattern). Two raw-pointer
//! conversions are unavoidable here:
//!
//! * obtaining the process `JavaVM` from the pointer the Android
//!   runtime installs, and
//! * viewing the app `Context` JNI global reference as a
//!   [`JObject`].
//!
//! Everything else goes through the safe `jni` surface so the rest
//! of the crate stays `unsafe`-free.
//!
//! ## Bootstrap contract
//!
//! The host app is responsible for making the `JavaVM` + `Context`
//! discoverable to [`ndk_context`] before any PAL method runs. On a
//! normal Android app this happens automatically when the shared
//! library is loaded; a host that loads the `.so` itself (or a
//! UniFFI-generated binding, Session 7) calls
//! `ndk_context::initialize_android_context(vm, context)` once at
//! startup. Every PAL backend then calls [`with_env`] to run a JNI
//! closure on the current thread, attaching it to the JVM if
//! needed.

use jni::objects::JObject;
use jni::{JNIEnv, JavaVM};

use crate::error::AndroidPalError;

/// Acquire the process-wide [`JavaVM`].
#[allow(unsafe_code)]
fn java_vm() -> Result<JavaVM, AndroidPalError> {
    let ctx = ndk_context::android_context();
    // SAFETY: `ndk_context::android_context().vm()` returns the
    // `JavaVM*` the Android runtime installed for this process
    // (set by the NDK glue at load time, or explicitly via
    // `ndk_context::initialize_android_context`). It is valid for
    // the whole process lifetime, and `JavaVM::from_raw` only
    // copies the pointer into the wrapper — it neither takes
    // ownership nor frees it — so no aliasing or lifetime invariant
    // is broken.
    unsafe { JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|e| AndroidPalError::Jni(format!("JavaVM::from_raw: {e}")))
}

/// View the host app's Android `Context` as a [`JObject`].
///
/// The returned object borrows a JNI global reference owned by the
/// Android runtime for the process lifetime; the PAL only reads
/// through it and never deletes it.
#[allow(unsafe_code)]
pub(crate) fn android_context<'a>() -> JObject<'a> {
    // SAFETY: `context()` is a JNI global reference to the app
    // `Context`, kept alive by the runtime for the whole process.
    // Wrapping it as a borrowed `JObject` does not take ownership.
    unsafe { JObject::from_raw(ndk_context::android_context().context().cast()) }
}

/// Run `f` with a [`JNIEnv`] attached to the current thread.
///
/// Attaching is cheap when the thread is already attached and is
/// detached automatically when the returned guard drops at the end
/// of the call.
pub(crate) fn with_env<F, T>(f: F) -> Result<T, AndroidPalError>
where
    F: FnOnce(&mut JNIEnv) -> Result<T, AndroidPalError>,
{
    let vm = java_vm()?;
    let mut guard = vm
        .attach_current_thread()
        .map_err(|e| AndroidPalError::Jni(format!("attach_current_thread: {e}")))?;
    f(&mut guard)
}
