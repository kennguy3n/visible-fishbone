package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/metrics"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// This file wires WS-5: the NoOps auto-promoter. It adapts the
// concrete persistence / metrics types to the small interfaces the
// rollout.Autopilot declares, and assembles the autopilot from config.
// main() runs Autopilot.Run leader-only (so exactly one replica sweeps)
// behind the cfg.RolloutAutopilot.Enabled default-OFF gate.

// rolloutAuditSink writes every rollout transition — operator-driven AND
// autopilot-driven — to the immutable audit log, so the staged-enablement
// history (including the autopilot's enrol/promote and the framework's
// auto-demote) is reconstructable for compliance. It satisfies
// rollout.TransitionSink.
type rolloutAuditSink struct {
	audit  repository.AuditLogRepository
	logger *slog.Logger
}

func newRolloutAuditSink(audit repository.AuditLogRepository, logger *slog.Logger) rolloutAuditSink {
	return rolloutAuditSink{audit: audit, logger: logger}
}

// OnTransition records the transition. It is best-effort: an audit
// failure is logged but never blocks or reverses the state change (the
// transition is already persisted by the time the sink runs).
func (s rolloutAuditSink) OnTransition(ctx context.Context, rec rollout.Record, from rollout.State) {
	details, err := json.Marshal(struct {
		Capability string `json:"capability"`
		From       string `json:"from"`
		To         string `json:"to"`
		Actor      string `json:"actor"`
		Reason     string `json:"reason,omitempty"`
	}{
		Capability: string(rec.Capability),
		From:       string(from),
		To:         string(rec.State),
		Actor:      rec.UpdatedBy,
		Reason:     rec.Reason,
	})
	if err != nil {
		// A record we cannot marshal still gets an empty-detail audit row
		// rather than none, so the transition is never silently unaudited.
		details = json.RawMessage(`{}`)
	}
	if _, err := s.audit.Append(ctx, rec.TenantID, repository.AuditEntry{
		TenantID:     rec.TenantID,
		Action:       "rollout.transition." + string(rec.State),
		ResourceType: "capability_rollout",
		Details:      details,
	}); err != nil && ctx.Err() == nil {
		s.logger.WarnContext(ctx, "rollout: audit append failed",
			slog.String("tenant_id", rec.TenantID.String()),
			slog.String("capability", string(rec.Capability)),
			slog.Any("error", err))
	}
}

// autopilotTenantLister adapts the paged TenantRepository to the
// rollout.TenantLister the autopilot consumes, returning the ids of every
// ACTIVE tenant (suspended/deleted tenants are never auto-promoted).
type autopilotTenantLister struct {
	tenants repository.TenantRepository
}

// ListActiveTenantIDs pages the full tenant list and keeps the active
// ones. It returns a non-nil slice on success.
func (l autopilotTenantLister) ListActiveTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	out := make([]uuid.UUID, 0)
	page := repository.Page{Limit: repository.MaxPageLimit, Order: repository.SortAsc}
	for {
		res, err := l.tenants.List(ctx, page)
		if err != nil {
			return nil, fmt.Errorf("list tenants: %w", err)
		}
		for _, t := range res.Items {
			if t.Status == repository.TenantStatusActive {
				out = append(out, t.ID)
			}
		}
		if res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	return out, nil
}

// autopilotMetricsObserver adapts the Prometheus metrics to
// rollout.AutopilotObserver, exporting the autopilot's per-action
// outcomes. newAutopilotObserver only ever constructs it with non-nil
// metric vectors; a disabled-metrics build gets the rollout no-op.
type autopilotMetricsObserver struct {
	transitions *prometheus.CounterVec
	blocked     *prometheus.CounterVec
}

func (o autopilotMetricsObserver) Enrolled(c rollout.Capability) {
	o.transitions.WithLabelValues(string(c), "enrol").Inc()
}

func (o autopilotMetricsObserver) Promoted(c rollout.Capability) {
	o.transitions.WithLabelValues(string(c), "promote").Inc()
}

func (o autopilotMetricsObserver) Demoted(c rollout.Capability) {
	o.transitions.WithLabelValues(string(c), "demote").Inc()
}

func (o autopilotMetricsObserver) PromotionBlocked(c rollout.Capability, reason string) {
	o.blocked.WithLabelValues(string(c), reason).Inc()
}

// newAutopilotObserver returns a metrics-backed observer, or the rollout
// no-op observer when metrics are disabled (mx == nil).
func newAutopilotObserver(mx *metrics.Metrics) rollout.AutopilotObserver {
	if mx == nil || mx.RolloutAutopilotTransitions == nil || mx.RolloutAutopilotPromotionsBlocked == nil {
		return rollout.NoopAutopilotObserver{}
	}
	return autopilotMetricsObserver{
		transitions: mx.RolloutAutopilotTransitions,
		blocked:     mx.RolloutAutopilotPromotionsBlocked,
	}
}

// buildRolloutAutopilot assembles the NoOps auto-promoter from config. It
// returns (nil, nil) when the autopilot is disabled (the default-OFF
// gate), so the caller simply skips scheduling it. svc is the same
// rollout.Service the operator API and per-capability gates use, and
// source is the shared MonitorMetricsRecorder the capabilities feed.
func buildRolloutAutopilot(
	cfg *config.Config,
	svc *rollout.Service,
	tenants repository.TenantRepository,
	source rollout.MonitorMetricsSource,
	mx *metrics.Metrics,
	logger *slog.Logger,
) (*rollout.Autopilot, error) {
	ac := cfg.RolloutAutopilot
	if !ac.Enabled {
		return nil, nil
	}

	caps, err := parseAutopilotCapabilities(ac.Capabilities)
	if err != nil {
		return nil, err
	}
	policy := rollout.AutopilotPolicy{
		Capabilities: caps,
		AutoEnrol:    ac.AutoEnrol,
		DwellWindow:  ac.DwellWindow,
		MinSamples:   ac.MinSamples,
		PromotionGuardrail: rollout.Threshold{
			MaxErrorRate: ac.MaxErrorRate,
			MaxDenyRate:  ac.MaxDenyRate,
			MinSamples:   ac.MinSamples,
		},
	}
	ap, err := rollout.NewAutopilot(svc, autopilotTenantLister{tenants: tenants}, source, policy,
		rollout.WithAutopilotLogger(logger),
		rollout.WithAutopilotObserver(newAutopilotObserver(mx)),
	)
	if err != nil {
		return nil, fmt.Errorf("rollout autopilot: %w", err)
	}
	return ap, nil
}

// parseAutopilotCapabilities maps the configured capability ids to
// rollout.Capability, defaulting to every governed capability when the
// list is empty. An unknown id is rejected so a typo fails boot rather
// than silently governing nothing.
func parseAutopilotCapabilities(ids []string) ([]rollout.Capability, error) {
	if len(ids) == 0 {
		return rollout.AllCapabilities(), nil
	}
	out := make([]rollout.Capability, 0, len(ids))
	for _, id := range ids {
		c := rollout.Capability(id)
		if !c.Valid() {
			return nil, fmt.Errorf("rollout autopilot: unknown capability %q in ROLLOUT_AUTOPILOT_CAPABILITIES", id)
		}
		out = append(out, c)
	}
	return out, nil
}

// autopilotSweepInterval returns the configured sweep cadence, falling
// back to one hour for a non-positive value (mirroring Autopilot.Run).
func autopilotSweepInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Hour
	}
	return d
}
