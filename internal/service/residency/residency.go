// Package residency implements data-residency enforcement for the
// ShieldNet Gateway control plane (Session 2C).
//
// A tenant may designate the region in which its regulated data —
// telemetry, policy bundles, and cold-storage archives — must remain.
// When a designation is in force, any attempt to write that data to a
// different region is rejected fail-closed: a write whose target
// region is unknown, or differs from the designated region, is denied
// rather than allowed. A tenant with no designation is unconstrained
// (residency is opt-in), which preserves the behaviour of tenants that
// pre-date the feature.
//
// The package is split into a pure-logic core (this file) and the
// service/persistence wiring (service.go). The core has no I/O so it
// is exhaustively unit-testable and safe to call on hot write paths.
package residency

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

// Region is a data-residency region identifier. Values are cloud-
// region-style tokens (e.g. "ap-southeast-1"); the type is a thin
// string wrapper so a region is never confused with an arbitrary
// string at a call site.
type Region string

// Plane names a class of tenant data subject to residency control.
// Used for fail-closed error messages and audit so an operator can
// see which data plane a rejected write targeted.
type Plane string

const (
	// PlaneTelemetry is per-tenant telemetry event data.
	PlaneTelemetry Plane = "telemetry"
	// PlanePolicyBundle is compiled, signed per-tenant policy bundles.
	PlanePolicyBundle Plane = "policy_bundle"
	// PlaneColdStorage is long-retention archived data (S3 cold tier).
	PlaneColdStorage Plane = "cold_storage"
	// PlaneRBIArtifact is artifact-transfer records produced by a
	// Remote Browser Isolation session (clipboard/file transfers).
	PlaneRBIArtifact Plane = "rbi_artifact"
)

var (
	// ErrInvalidRegion is returned by ValidateRegion for a malformed
	// region token.
	ErrInvalidRegion = errors.New("residency: invalid region")
	// ErrUnsupportedRegion is returned when a region is syntactically
	// valid but not one this build knows how to keep data within.
	ErrUnsupportedRegion = errors.New("residency: unsupported region")
	// ErrResidencyViolation is the fail-closed rejection: the write's
	// target region is unknown or differs from the tenant's
	// designated residency region.
	ErrResidencyViolation = errors.New("residency: cross-region write rejected")
)

// regionToken bounds a region identifier to a conservative,
// injection-proof shape (lowercase alphanumerics and hyphens). It is
// deliberately lenient on the *set* of regions — any well-formed token
// is accepted by ValidateRegion — so existing free-form tenant region
// strings (e.g. "us-east") keep validating. Strict membership is the
// job of RequireSupported, used only by the opt-in residency config.
var regionToken = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})$`)

// Jurisdiction couples a residency region to the regulatory regime and
// the compliance frameworks (see internal/service/compliance) that
// apply to data kept there. It is what makes a region "supported": a
// region SNG can attach residency + compliance meaning to.
type Jurisdiction struct {
	Region  Region
	Country string
	// Frameworks lists the compliance framework identifiers most
	// relevant to data held in this region. The strings match
	// compliance.ComplianceFramework values.
	Frameworks []string
}

// catalog is the set of first-class residency regions and their
// jurisdictions, aligned with the Session 2C regional compliance
// frameworks. Cold-storage / telemetry kept in one of these regions
// can be attested against the listed frameworks.
//
// Regions outside this catalog are still ENFORCEABLE — EnforceWrite
// compares the designated and target regions by exact match regardless
// of catalog membership — they simply carry no jurisdiction metadata
// and cannot be selected as an opt-in residency designation.
var catalog = map[Region]Jurisdiction{
	"ap-southeast-1": {Region: "ap-southeast-1", Country: "SG", Frameworks: []string{"PDPA", "CSA_CE"}},
	"ap-southeast-7": {Region: "ap-southeast-7", Country: "TH", Frameworks: []string{"PDPA"}},
	"ap-southeast-5": {Region: "ap-southeast-5", Country: "MY", Frameworks: []string{"PDPA"}},
	"me-central-1":   {Region: "me-central-1", Country: "AE", Frameworks: []string{"NESA_TDRA"}},
	"eu-central-1":   {Region: "eu-central-1", Country: "DE", Frameworks: []string{"BDSG_GDPR"}},
	"eu-central-2":   {Region: "eu-central-2", Country: "CH", Frameworks: []string{"FDPIC_NDSG"}},
}

// Normalize trims surrounding whitespace and lowercases a region so
// "  AP-Southeast-1 " and "ap-southeast-1" compare equal. Comparison
// and lookup always go through Normalize.
func Normalize(r Region) Region {
	return Region(strings.ToLower(strings.TrimSpace(string(r))))
}

// ValidateRegion checks that r is a well-formed region token. The
// empty string is rejected here (callers that permit "unset" should
// special-case empty before calling). It does NOT require catalog
// membership — see RequireSupported for that — so legacy free-form
// regions remain valid.
func ValidateRegion(r Region) error {
	n := Normalize(r)
	if n == "" {
		return ErrInvalidRegion
	}
	if !regionToken.MatchString(string(n)) {
		return ErrInvalidRegion
	}
	return nil
}

// RequireSupported returns the Jurisdiction for r, or an error if r is
// malformed (ErrInvalidRegion) or not a catalogued residency region
// (ErrUnsupportedRegion). Used to validate an opt-in residency
// designation, which — unlike the loose tenants.region column — must
// be a region SNG can actually keep data within.
func RequireSupported(r Region) (Jurisdiction, error) {
	if err := ValidateRegion(r); err != nil {
		return Jurisdiction{}, err
	}
	j, ok := catalog[Normalize(r)]
	if !ok {
		return Jurisdiction{}, ErrUnsupportedRegion
	}
	return j, nil
}

// SupportedRegions returns the catalogued residency regions sorted by
// region identifier, so the order is deterministic across calls (the
// catalog is a map, whose iteration order is not). Suitable for surfacing
// directly in config UIs/APIs without the caller re-sorting.
func SupportedRegions() []Jurisdiction {
	out := make([]Jurisdiction, 0, len(catalog))
	for _, j := range catalog {
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Region < out[j].Region })
	return out
}

// EnforceWrite is the fail-closed residency check. Given a tenant's
// designated region and the region a write is about to land in, it
// returns nil only when the write is permitted:
//
//   - designated == "" : residency is not configured for this tenant,
//     so there is nothing to enforce — the write is allowed (opt-in).
//   - designated != "" && target == "" : the write's location cannot be
//     proven, so it is DENIED (fail-closed).
//   - designated != "" && target != designated : a cross-region write,
//     DENIED.
//   - designated != "" && target == designated : allowed.
//
// Comparison is region-normalized. The returned error wraps
// ErrResidencyViolation so callers can errors.Is it while still
// surfacing the specific plane/region in logs.
func EnforceWrite(designated, target Region, plane Plane) error {
	d := Normalize(designated)
	if d == "" {
		return nil
	}
	t := Normalize(target)
	if t == "" {
		return &Violation{Plane: plane, Designated: d, Target: t, reason: "write target region is unknown"}
	}
	if t != d {
		return &Violation{Plane: plane, Designated: d, Target: t, reason: "write target region differs from designated region"}
	}
	return nil
}

// Violation is the structured fail-closed rejection returned by
// EnforceWrite. It implements error and unwraps to
// ErrResidencyViolation.
type Violation struct {
	Plane      Plane
	Designated Region
	Target     Region
	reason     string
}

func (v *Violation) Error() string {
	return "residency: " + string(v.Plane) + " write to region " +
		quote(string(v.Target)) + " rejected; tenant residency is " +
		quote(string(v.Designated)) + " (" + v.reason + ")"
}

// Unwrap lets errors.Is(err, ErrResidencyViolation) match.
func (v *Violation) Unwrap() error { return ErrResidencyViolation }

func quote(s string) string {
	if s == "" {
		return `""`
	}
	return `"` + s + `"`
}
