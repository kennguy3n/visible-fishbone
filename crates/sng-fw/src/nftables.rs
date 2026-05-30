//! nftables apply / inspect backend.
//!
//! The firewall engine sits behind a [`NftablesBackend`] trait so:
//!
//! * Production builds shell out to `nft -f -` and apply the
//!   compiled script atomically (the kernel implements
//!   `nft -f` as a transactional commit — either every rule
//!   loads or none of them do).
//! * Unit and integration tests bind a [`MockNftables`] that
//!   captures the script bytes for assertion without requiring
//!   root or an actual nftables kernel module. This lets the
//!   bulk of the firewall logic be tested in CI on a userland-
//!   only environment.
//!
//! The trait is intentionally narrow — one `apply` for installing
//! a script and one `inspect` for listing the current ruleset.
//! Higher-level operations (live rule diffing, hot-swap diffing)
//! live in [`crate::engine::FirewallEngine`] which composes the
//! backend with the compiled-script source of truth.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use crate::error::FirewallError;

/// A blob of nftables rule text ready to be applied. Carries
/// the byte payload plus the SHA-256 of the payload so the
/// engine can hash-compare two compilations without re-walking
/// the rule list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftablesScript {
    /// The script text (UTF-8, newline-separated, no trailing
    /// shell-isms — pure nftables expressions). The shell-out
    /// backend pipes this through `nft -f -` verbatim.
    pub bytes: Vec<u8>,
    /// SHA-256 of [`Self::bytes`]. Used by the engine's hot-
    /// swap path to skip applying an identical script.
    pub digest: [u8; 32],
}

impl NftablesScript {
    /// Wrap an existing byte buffer; computes the digest on
    /// construction.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let digest = sha256(&bytes);
        Self { bytes, digest }
    }

    /// View the script as a UTF-8 string. Returns `None` if the
    /// payload is not valid UTF-8 — this should never happen for
    /// compiler-produced scripts but is checked defensively for
    /// callers that hand-build a payload.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Apply / inspect the kernel's nftables ruleset. Implementations
/// are async because the production backend forks `nft` as a
/// child process; the test backend is in-memory but keeps the
/// async signature so the call sites are identical.
#[async_trait]
pub trait NftablesBackend: Send + Sync + std::fmt::Debug {
    /// Apply the supplied script. The kernel commits the script
    /// transactionally — either every rule installs or none do.
    async fn apply(&self, script: &NftablesScript) -> Result<(), FirewallError>;

    /// Dump the current ruleset as a script. Used by the engine
    /// for diff-based hot-swap detection on platforms where the
    /// kernel does not expose a stable digest of its rule set.
    async fn inspect(&self) -> Result<NftablesScript, FirewallError>;
}

/// Production backend — shells out to `nft`. The binary path is
/// configurable so deployments that ship a vendored `nft` (e.g.
/// inside the SNG appliance image) can point at a non-PATH
/// location.
#[derive(Clone, Debug)]
pub struct ShellNftables {
    /// Path to the `nft` binary. Defaults to `"nft"` so the
    /// shell-out resolves through `PATH`.
    pub binary: String,
    /// Optional argument prefix prepended to every invocation
    /// (e.g. `["--check"]` for dry-run mode). Most deployments
    /// leave this empty.
    pub args: Vec<String>,
}

impl Default for ShellNftables {
    fn default() -> Self {
        Self {
            binary: "nft".into(),
            args: Vec::new(),
        }
    }
}

impl ShellNftables {
    /// Construct with the default binary name.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an explicit binary path.
    #[must_use]
    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            args: Vec::new(),
        }
    }
}

#[async_trait]
impl NftablesBackend for ShellNftables {
    async fn apply(&self, script: &NftablesScript) -> Result<(), FirewallError> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        let mut cmd = Command::new(&self.binary);
        cmd.args(&self.args);
        cmd.arg("-f");
        cmd.arg("-");
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| FirewallError::Io(format!("spawn {}: {e}", self.binary)))?;
        // Take the stdin handle so the child can be awaited.
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| FirewallError::Io("nft child has no stdin".into()))?;
        stdin
            .write_all(&script.bytes)
            .await
            .map_err(|e| FirewallError::Io(format!("write to {}: {e}", self.binary)))?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| FirewallError::Io(format!("wait {}: {e}", self.binary)))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::NftablesApply(format!(
                "{} exited with {}: {}",
                self.binary,
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    async fn inspect(&self) -> Result<NftablesScript, FirewallError> {
        use tokio::process::Command;
        let mut cmd = Command::new(&self.binary);
        cmd.args(&self.args);
        cmd.arg("list");
        cmd.arg("ruleset");
        let output = cmd
            .output()
            .await
            .map_err(|e| FirewallError::Io(format!("spawn {}: {e}", self.binary)))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::NftablesApply(format!(
                "{} list ruleset exited with {}: {}",
                self.binary,
                output.status,
                stderr.trim()
            )));
        }
        Ok(NftablesScript::new(output.stdout))
    }
}

/// In-memory backend for tests — records every applied script
/// and serves the most recent one on inspect.
#[derive(Clone, Debug, Default)]
pub struct MockNftables {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    applied: Vec<NftablesScript>,
    apply_should_fail: Option<String>,
}

impl MockNftables {
    /// Empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Force the next [`NftablesBackend::apply`] call to fail
    /// with the supplied message. The mock reverts to success
    /// after one failed call.
    pub fn fail_next_apply(&self, message: impl Into<String>) {
        if let Ok(mut s) = self.state.lock() {
            s.apply_should_fail = Some(message.into());
        }
    }

    /// All scripts applied so far, in order.
    #[must_use]
    pub fn applied(&self) -> Vec<NftablesScript> {
        self.state
            .lock()
            .map(|s| s.applied.clone())
            .unwrap_or_default()
    }

    /// Number of applied scripts.
    #[must_use]
    pub fn apply_count(&self) -> usize {
        self.state
            .lock()
            .map(|s| s.applied.len())
            .unwrap_or_default()
    }

    /// Last applied script, if any.
    #[must_use]
    pub fn last(&self) -> Option<NftablesScript> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.applied.last().cloned())
    }
}

#[async_trait]
impl NftablesBackend for MockNftables {
    async fn apply(&self, script: &NftablesScript) -> Result<(), FirewallError> {
        let mut s = self
            .state
            .lock()
            .map_err(|_| FirewallError::Io("mock nftables state poisoned".into()))?;
        if let Some(msg) = s.apply_should_fail.take() {
            return Err(FirewallError::NftablesApply(msg));
        }
        s.applied.push(script.clone());
        Ok(())
    }

    async fn inspect(&self) -> Result<NftablesScript, FirewallError> {
        let s = self
            .state
            .lock()
            .map_err(|_| FirewallError::Io("mock nftables state poisoned".into()))?;
        s.applied
            .last()
            .cloned()
            .ok_or_else(|| FirewallError::Io("no script has been applied yet".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn make_script(bytes: &[u8]) -> NftablesScript {
        NftablesScript::new(bytes.to_vec())
    }

    #[test]
    fn script_digest_is_deterministic() {
        let a = make_script(b"add table inet x");
        let b = make_script(b"add table inet x");
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn script_digest_changes_with_content() {
        let a = make_script(b"add table inet x");
        let b = make_script(b"add table inet y");
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn script_as_str_returns_utf8_payload() {
        let s = make_script(b"add table inet x");
        assert_eq!(s.as_str(), Some("add table inet x"));
    }

    #[test]
    fn script_as_str_returns_none_on_invalid_utf8() {
        let s = make_script(&[0xFF, 0xFE]);
        assert_eq!(s.as_str(), None);
    }

    #[tokio::test]
    async fn mock_apply_captures_script() {
        let m = MockNftables::new();
        let s = make_script(b"add table inet x");
        m.apply(&s).await.unwrap();
        assert_eq!(m.apply_count(), 1);
        assert_eq!(m.last().unwrap(), s);
    }

    #[tokio::test]
    async fn mock_apply_multiple_preserves_order() {
        let m = MockNftables::new();
        let a = make_script(b"a");
        let b = make_script(b"b");
        let c = make_script(b"c");
        m.apply(&a).await.unwrap();
        m.apply(&b).await.unwrap();
        m.apply(&c).await.unwrap();
        let all = m.applied();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], a);
        assert_eq!(all[1], b);
        assert_eq!(all[2], c);
    }

    #[tokio::test]
    async fn mock_fail_next_apply_returns_error() {
        let m = MockNftables::new();
        let s = make_script(b"x");
        m.fail_next_apply("kernel rejected");
        let e = m.apply(&s).await.unwrap_err();
        assert!(
            matches!(e, FirewallError::NftablesApply(ref msg) if msg.contains("kernel rejected"))
        );
        // Subsequent calls succeed — failure is one-shot.
        m.apply(&s).await.unwrap();
        assert_eq!(m.apply_count(), 1);
    }

    #[tokio::test]
    async fn mock_inspect_returns_last_applied() {
        let m = MockNftables::new();
        m.apply(&make_script(b"a")).await.unwrap();
        m.apply(&make_script(b"b")).await.unwrap();
        let last = m.inspect().await.unwrap();
        assert_eq!(last.as_str(), Some("b"));
    }

    #[tokio::test]
    async fn mock_inspect_errors_when_empty() {
        let m = MockNftables::new();
        let e = m.inspect().await.unwrap_err();
        assert!(matches!(e, FirewallError::Io(_)));
    }

    #[test]
    fn shell_nftables_defaults_to_nft_on_path() {
        let s = ShellNftables::default();
        assert_eq!(s.binary, "nft");
        assert!(s.args.is_empty());
    }

    #[test]
    fn shell_nftables_with_binary_uses_supplied_path() {
        let s = ShellNftables::with_binary("/usr/sbin/nft");
        assert_eq!(s.binary, "/usr/sbin/nft");
    }

    #[tokio::test]
    async fn shell_nftables_apply_returns_io_when_binary_missing() {
        // Force a binary that does not exist — the spawn fails
        // with an io error.
        let s = ShellNftables::with_binary("/nonexistent/nft-binary-for-tests");
        let script = make_script(b"add table inet x");
        let e = s.apply(&script).await.unwrap_err();
        assert!(matches!(e, FirewallError::Io(_)));
    }
}
