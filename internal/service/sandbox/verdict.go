// Package sandbox orchestrates zero-day file analysis: it submits
// unknown files to a detonation sandbox (Cuckoo, CAPEv2, or a
// bring-your-own webhook provider), persists the resulting verdicts
// keyed by file SHA-256, and serves cached verdicts back to the SWG
// malware stage so a file is detonated at most once across the
// fleet.
//
// The control plane owns submission + persistence; the data plane
// (crates/sng-swg/src/malware.rs) asks for a verdict by hash and,
// on a miss, hands the unknown file to this service. The provider
// interface (sandbox/providers) abstracts the concrete sandbox so
// an operator can switch backends without touching the service.
package sandbox

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// Classification is the high-level disposition a sandbox assigns to
// a detonated file. The string forms are stable wire/telemetry
// values shared with the data plane and the persisted column, so do
// not rename them without a migration + a data-plane change.
type Classification string

const (
	// ClassUnknown is the zero value: no verdict has been reached
	// yet (submission pending, or the file was never submitted).
	ClassUnknown Classification = "unknown"
	// ClassClean means the sandbox observed no malicious behaviour.
	ClassClean Classification = "clean"
	// ClassSuspicious means the sandbox saw risky-but-inconclusive
	// behaviour; the SWG policy decides whether to block or warn.
	ClassSuspicious Classification = "suspicious"
	// ClassMalicious means the sandbox confirmed malicious behaviour.
	ClassMalicious Classification = "malicious"
	// ClassTimeout means analysis did not finish within the
	// provider's detonation window. Treated as fail-open or
	// fail-closed per the SWG configuration, not here.
	ClassTimeout Classification = "timeout"
)

// Valid reports whether c is one of the known classifications.
func (c Classification) Valid() bool {
	switch c {
	case ClassUnknown, ClassClean, ClassSuspicious, ClassMalicious, ClassTimeout:
		return true
	default:
		return false
	}
}

// Status is the lifecycle state of a submission while the sandbox
// is still working. Once a submission resolves it carries a
// Classification instead.
type Status string

const (
	// StatusPending means the file was accepted and is queued or
	// detonating; poll again later.
	StatusPending Status = "pending"
	// StatusComplete means analysis finished; the Verdict is final.
	StatusComplete Status = "complete"
	// StatusError means the provider failed the analysis (bad file,
	// provider outage). The caller may retry submission.
	StatusError Status = "error"
)

// Verdict is the result of detonating one file, keyed by its
// SHA-256. Confidence is in [0,1]; a provider that does not report a
// score should set 1.0 for a definitive clean/malicious verdict and
// a lower value for suspicious.
type Verdict struct {
	// SHA256 is the lowercase hex digest of the analysed file. It is
	// the cache + persistence key and is tenant-independent (the same
	// bytes detonate to the same verdict), though the row is stored
	// per tenant for isolation and audit.
	SHA256 string
	// Classification is the disposition. Never ClassUnknown on a
	// resolved verdict.
	Classification Classification
	// Confidence is the provider's confidence in [0,1].
	Confidence float64
	// Provider is the provider id that produced the verdict
	// ("cuckoo", "cape", "generic"), recorded for audit and so a
	// verdict from a decommissioned provider can be re-evaluated.
	Provider string
	// SandboxID is the provider-side analysis id, retained so an
	// operator can pull the full report from the sandbox UI.
	SandboxID string
	// Summary is a short human-readable description of the dominant
	// signal (e.g. "ransomware: mass file rename"). Optional.
	Summary string
	// AnalyzedAt is when the provider finished analysis.
	AnalyzedAt time.Time
}

// normalize lowercases and trims the hash so cache lookups and
// persisted rows use one canonical form regardless of how the
// caller cased the digest.
func (v *Verdict) normalize() {
	v.SHA256 = strings.ToLower(strings.TrimSpace(v.SHA256))
	v.Provider = strings.TrimSpace(v.Provider)
}

// Blocking reports whether this verdict should cause the SWG to
// block the file outright. Only a confirmed-malicious verdict blocks
// here; suspicious/timeout handling is a policy decision made by the
// data plane against its configured posture.
func (v Verdict) Blocking() bool {
	return v.Classification == ClassMalicious
}

// Disposition is the fail-closed allow/deny decision the data plane
// acts on for a file. It is deliberately ternary: a file is only
// released (DispositionAllow) when a sandbox has *resolved* it clean.
// Anything else — pending analysis, an unknown/never-submitted file,
// a provider error, or a suspicious/malicious/timeout verdict — is
// not clean and must not be released on the strength of the sandbox
// alone.
type Disposition string

const (
	// DispositionAllow means a resolved, clean verdict exists: the
	// file is safe to release as far as the sandbox is concerned.
	DispositionAllow Disposition = "allow"
	// DispositionPending means a submission exists but has not
	// resolved yet; the caller should hold or re-poll. It is treated
	// as not-clean for any fail-closed posture.
	DispositionPending Disposition = "pending"
	// DispositionDeny means the file is not clean: a malicious,
	// suspicious, timeout, unknown, or errored verdict. Fail-closed
	// callers block on this.
	DispositionDeny Disposition = "deny"
)

// Clean reports whether the file may be released. Only DispositionAllow
// is clean; pending and deny are both not-clean (fail-closed).
func (d Disposition) Clean() bool { return d == DispositionAllow }

// dispositionFor maps a submission row's status and verdict onto the
// fail-closed ternary decision. Only a *complete*, clean verdict is
// releasable (DispositionAllow). A still-pending submission yields
// DispositionPending so the caller holds and re-polls. Every other
// state — a provider error (terminal: it will never resolve), or a
// complete suspicious / malicious / timeout / unknown verdict — yields
// DispositionDeny. An errored row must deny rather than pend: it is
// terminal, so reporting it pending would make the caller re-poll a
// verdict that can never resolve.
func dispositionFor(status Status, v Verdict) Disposition {
	switch status {
	case StatusComplete:
		if v.Classification == ClassClean {
			return DispositionAllow
		}
		// Complete but suspicious / malicious / timeout / unknown:
		// not clean.
		return DispositionDeny
	case StatusPending:
		// Genuinely in-flight: hold and re-poll. Not clean.
		return DispositionPending
	default:
		// StatusError or any unexpected/empty state is terminal and
		// not clean; deny fail-closed rather than pend forever.
		return DispositionDeny
	}
}

// Submission is a request to detonate one file. The bytes are
// carried by reference to Content so a large upload is not copied
// through the service; providers stream it to their API.
type Submission struct {
	// TenantID scopes the resulting verdict row.
	TenantID uuid.UUID
	// SHA256 is the precomputed lowercase hex digest. Required: the
	// service refuses a submission without it rather than hashing
	// large payloads on the hot path (the SWG already has the digest
	// from its malware lookup).
	SHA256 string
	// Filename is the original file name, forwarded to the provider
	// for report context. Optional.
	Filename string
	// Content is the raw file bytes to detonate.
	Content []byte
}
