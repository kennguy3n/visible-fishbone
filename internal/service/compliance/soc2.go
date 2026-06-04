// soc2.go implements the SOC2 Type II evidence collector: it gathers
// per-control evidence artifacts from pluggable sources and assembles
// them into a single EvidenceBundle ready to be signed and archived by
// the EvidenceService.
//
// SOC2 trust-services controls covered (per the Session J spec):
//
//	CC6.1  Logical access      — RBAC policy + user access reviews
//	CC6.2  System operations   — deployment logs + change approvals
//	CC6.3  Change management    — policy change history + simulations
//	CC7.1  Monitoring           — alert configs + incident playbooks
//	CC8.1  Availability         — uptime metrics + HA config + backups
//
// Sources are injected as narrow functions so this package does not
// depend on the tenant-scoped rbac/audit/policy services directly; the
// wiring layer (cmd/sng-control) adapts the real services into these
// functions. A control whose sources are not wired is simply omitted
// from the bundle, and the scheduler's gap detection flags the missing
// evidence — an honest "we did not collect X" rather than a fabricated
// artifact.
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

// SOC2 control identifiers.
const (
	ControlCC61 = "CC6.1"
	ControlCC62 = "CC6.2"
	ControlCC63 = "CC6.3"
	ControlCC71 = "CC7.1"
	ControlCC81 = "CC8.1"
)

// ExpectedControls is the canonical, ordered set of controls a complete
// SOC2 evidence bundle is expected to cover. Gap detection compares a
// bundle's actual controls against this list.
var ExpectedControls = []string{
	ControlCC61, ControlCC62, ControlCC63, ControlCC71, ControlCC81,
}

// EvidenceFunc exports one named piece of control evidence. It returns
// any JSON-marshalable value (a struct, slice, or map). Returning a nil
// value with a nil error means "nothing to export" and the artifact is
// skipped.
type EvidenceFunc func(ctx context.Context) (any, error)

// ControlEvidenceProvider produces the artifacts for a single SOC2
// control. Implementations must be safe to call repeatedly.
type ControlEvidenceProvider interface {
	// Control returns the SOC2 control ID this provider serves.
	Control() string
	// Collect gathers the control's artifacts. A provider should
	// return an error only when evidence collection genuinely failed;
	// an empty slice with nil error is a valid (if gap-worthy) result.
	Collect(ctx context.Context) ([]EvidenceArtifact, error)
}

// namedExport pairs an artifact name/kind with the function that
// produces its payload.
type namedExport struct {
	name string
	kind string
	fn   EvidenceFunc
}

// funcProvider is the standard ControlEvidenceProvider: a control ID
// plus an ordered list of named exports. Emission order is preserved so
// CanonicalBytes (and therefore the signature) is deterministic.
type funcProvider struct {
	control string
	exports []namedExport
}

func (p *funcProvider) Control() string { return p.control }

func (p *funcProvider) Collect(ctx context.Context) ([]EvidenceArtifact, error) {
	artifacts := make([]EvidenceArtifact, 0, len(p.exports))
	for _, e := range p.exports {
		if err := ctx.Err(); err != nil {
			return artifacts, err
		}
		val, err := e.fn(ctx)
		if err != nil {
			return artifacts, fmt.Errorf("%s/%s: %w", p.control, e.name, err)
		}
		if val == nil {
			continue
		}
		data, err := json.Marshal(val)
		if err != nil {
			return artifacts, fmt.Errorf("%s/%s: marshal: %w", p.control, e.name, err)
		}
		artifacts = append(artifacts, EvidenceArtifact{
			Control: p.control,
			Name:    e.name,
			Kind:    e.kind,
			Data:    json.RawMessage(data),
		})
	}
	return artifacts, nil
}

// Sources bundles the evidence-export functions for every SOC2 control.
// Each field is optional: a nil function means that input is not wired,
// and the corresponding artifact is omitted (and later flagged as a
// gap). The wiring layer populates these from the real services and
// platform configuration.
type Sources struct {
	// CC6.1 Logical access.
	RBACPolicy    EvidenceFunc // exported RBAC roles/permissions
	AccessReviews EvidenceFunc // periodic user-access review records

	// CC6.2 System operations.
	DeploymentLogs  EvidenceFunc // deployment / release log export
	ChangeApprovals EvidenceFunc // change-approval records (audit)

	// CC6.3 Change management.
	PolicyChangeHistory EvidenceFunc // policy version history
	SimulationResults   EvidenceFunc // policy simulation/dry-run results

	// CC7.1 Monitoring.
	AlertConfigs      EvidenceFunc // alerting rules/thresholds
	IncidentPlaybooks EvidenceFunc // incident-response playbooks

	// CC8.1 Availability.
	UptimeMetrics   EvidenceFunc // uptime / SLO metrics
	HAConfig        EvidenceFunc // high-availability configuration
	BackupSchedules EvidenceFunc // backup schedule / retention config
}

// providers builds the ordered ControlEvidenceProvider list from the
// wired sources, skipping exports whose source function is nil.
func (s Sources) providers() []ControlEvidenceProvider {
	build := func(control string, exports ...namedExport) ControlEvidenceProvider {
		wired := make([]namedExport, 0, len(exports))
		for _, e := range exports {
			if e.fn != nil {
				wired = append(wired, e)
			}
		}
		return &funcProvider{control: control, exports: wired}
	}
	return []ControlEvidenceProvider{
		build(ControlCC61,
			namedExport{"rbac_policy", ArtifactJSONExport, s.RBACPolicy},
			namedExport{"user_access_reviews", ArtifactJSONExport, s.AccessReviews},
		),
		build(ControlCC62,
			namedExport{"deployment_logs", ArtifactJSONExport, s.DeploymentLogs},
			namedExport{"change_approvals", ArtifactJSONExport, s.ChangeApprovals},
		),
		build(ControlCC63,
			namedExport{"policy_change_history", ArtifactJSONExport, s.PolicyChangeHistory},
			namedExport{"simulation_results", ArtifactJSONExport, s.SimulationResults},
		),
		build(ControlCC71,
			namedExport{"alert_configs", ArtifactConfigSnapshot, s.AlertConfigs},
			namedExport{"incident_playbooks", ArtifactJSONExport, s.IncidentPlaybooks},
		),
		build(ControlCC81,
			namedExport{"uptime_metrics", ArtifactJSONExport, s.UptimeMetrics},
			namedExport{"ha_config", ArtifactConfigSnapshot, s.HAConfig},
			namedExport{"backup_schedules", ArtifactConfigSnapshot, s.BackupSchedules},
		),
	}
}

// SOC2EvidenceCollector orchestrates per-control evidence providers into
// a single signed-ready EvidenceBundle.
type SOC2EvidenceCollector struct {
	providers []ControlEvidenceProvider
	logger    *slog.Logger
	now       func() time.Time
}

// NewSOC2Collector builds a collector from a Sources set.
func NewSOC2Collector(src Sources, logger *slog.Logger, opts ...CollectorOption) *SOC2EvidenceCollector {
	return newCollector(src.providers(), logger, opts...)
}

// NewSOC2CollectorWithProviders builds a collector from explicit
// providers (used by tests and for custom control sets).
func NewSOC2CollectorWithProviders(providers []ControlEvidenceProvider, logger *slog.Logger, opts ...CollectorOption) *SOC2EvidenceCollector {
	return newCollector(providers, logger, opts...)
}

func newCollector(providers []ControlEvidenceProvider, logger *slog.Logger, opts ...CollectorOption) *SOC2EvidenceCollector {
	if logger == nil {
		logger = slog.Default()
	}
	c := &SOC2EvidenceCollector{
		providers: providers,
		logger:    logger,
		now:       func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CollectorOption customises a SOC2EvidenceCollector.
type CollectorOption func(*SOC2EvidenceCollector)

// WithCollectorClock overrides the wall-clock (tests).
func WithCollectorClock(now func() time.Time) CollectorOption {
	return func(c *SOC2EvidenceCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// CollectResult is the outcome of a collection run: the assembled
// bundle plus the per-control errors that occurred. The bundle always
// contains every artifact that WAS collected, even when some controls
// failed — partial evidence is still useful and the failures are
// surfaced for alerting.
type CollectResult struct {
	Bundle        *EvidenceBundle
	FailedControl map[string]error
}

// MissingControls reports expected controls that produced no artifacts
// in this run (whether because they failed or were not wired).
func (r CollectResult) MissingControls() []string {
	present := make(map[string]struct{})
	for _, c := range r.Bundle.Controls() {
		present[c] = struct{}{}
	}
	var missing []string
	for _, c := range ExpectedControls {
		if _, ok := present[c]; !ok {
			missing = append(missing, c)
		}
	}
	sort.Strings(missing)
	return missing
}

// Collect runs every provider and assembles an EvidenceBundle of the
// given collection type. It does not abort on a single control's
// failure: failures are recorded in CollectResult.FailedControl and the
// successful artifacts are still returned. An error is returned only if
// the context is cancelled.
func (c *SOC2EvidenceCollector) Collect(ctx context.Context, collectionType string) (CollectResult, error) {
	bundle := NewBundle(collectionType, c.now())
	failed := make(map[string]error)

	for _, p := range c.providers {
		if err := ctx.Err(); err != nil {
			return CollectResult{Bundle: bundle, FailedControl: failed}, err
		}
		artifacts, err := p.Collect(ctx)
		// Always keep whatever was gathered before the error.
		for _, a := range artifacts {
			bundle.Add(a)
		}
		if err != nil {
			failed[p.Control()] = err
			c.logger.Error("compliance: control evidence collection failed",
				slog.String("control", p.Control()),
				slog.String("collection_type", collectionType),
				slog.Any("error", err))
		}
	}

	if missing := (CollectResult{Bundle: bundle}).MissingControls(); len(missing) > 0 {
		c.logger.Warn("compliance: evidence bundle missing controls",
			slog.String("collection_type", collectionType),
			slog.Any("missing_controls", missing))
	}

	return CollectResult{Bundle: bundle, FailedControl: failed}, nil
}

// errNoProviders is returned by Validate when a collector has no
// providers at all — a configuration error worth surfacing at startup.
var errNoProviders = errors.New("compliance: SOC2 collector has no providers")

// Validate checks the collector is minimally configured. Intended for
// call at wiring time.
func (c *SOC2EvidenceCollector) Validate() error {
	if len(c.providers) == 0 {
		return errNoProviders
	}
	return nil
}
