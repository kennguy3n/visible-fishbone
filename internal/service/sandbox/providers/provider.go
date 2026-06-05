// Package providers holds the detonation-sandbox backend adapters
// behind a single Provider interface. The sandbox service depends
// only on this interface, so an operator can select Cuckoo, CAPEv2,
// or a bring-your-own webhook provider without the service knowing
// which one is wired.
//
// Every adapter degrades gracefully: a misconfigured or unreachable
// backend returns an error from Submit/Poll rather than panicking,
// and the service treats that as "no verdict available" (fail-open
// at the service layer; the SWG applies its own posture).
package providers

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Classification mirrors sandbox.Classification as a plain string so
// the providers package does not import the parent service package
// (which would be a dependency cycle: service imports providers).
// The service maps these strings onto its typed Classification.
type Classification string

const (
	ClassUnknown    Classification = "unknown"
	ClassClean      Classification = "clean"
	ClassSuspicious Classification = "suspicious"
	ClassMalicious  Classification = "malicious"
	ClassTimeout    Classification = "timeout"
)

// Status is the lifecycle state of a submission, mirroring
// sandbox.Status for the same decoupling reason.
type Status string

const (
	StatusPending  Status = "pending"
	StatusComplete Status = "complete"
	StatusError    Status = "error"
)

// SubmitResult is returned by Submit: the provider-side analysis id
// to poll, plus the initial status. A provider that detonates
// synchronously may return StatusComplete with a populated Result.
type SubmitResult struct {
	SandboxID string
	Status    Status
	// Result is set only when Status is StatusComplete (synchronous
	// providers). For asynchronous providers it is the zero value
	// and the caller polls SandboxID.
	Result PollResult
}

// PollResult is the outcome of polling a submission.
type PollResult struct {
	Status         Status
	Classification Classification
	Confidence     float64
	Summary        string
	AnalyzedAt     time.Time
}

// File is the file to detonate, passed to Submit.
type File struct {
	SHA256   string
	Filename string
	Content  []byte
}

// Provider is the detonation-sandbox backend contract.
type Provider interface {
	// ID returns the stable provider id ("cuckoo", "cape",
	// "generic") recorded on each verdict.
	ID() string
	// Submit hands a file to the sandbox and returns the analysis id
	// to poll. It must not block on detonation completing.
	Submit(ctx context.Context, f File) (SubmitResult, error)
	// Poll fetches the current status of a previously submitted
	// analysis.
	Poll(ctx context.Context, sandboxID string) (PollResult, error)
}

// ErrProviderUnavailable is returned by a provider whose backend is
// not configured or not reachable. The service treats it as a soft
// miss (no verdict) rather than a hard failure.
var ErrProviderUnavailable = errors.New("sandbox provider unavailable")

// HTTPDoer is the seam tests use to inject a mock HTTP client, and
// the real adapters use a *http.Client. It mirrors the
// integration-connector convention so the providers stay unit
// testable without standing up a real sandbox.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// NormalizeConfidence clamps a provider-reported score into [0,1].
// Providers report scores on different scales (0-10, 0-100); the
// adapter divides before calling this, and this guards against an
// out-of-range value poisoning downstream math.
func NormalizeConfidence(score float64) float64 {
	switch {
	case score < 0:
		return 0
	case score > 1:
		return 1
	default:
		return score
	}
}
