package complianceauto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Default scheduling parameters. Evidence collection is bounded and
// cheap: one sweep per DefaultInterval performs a fixed handful of
// read-only repository calls per tenant. At 5,000 SME tenants a daily
// sweep is ~5,000 × ~5 indexed reads — comfortably within a no-ops
// budget — and never runs on a request path (it is leader-gated and
// background-only). DefaultInitialDelay staggers the first sweep after a
// node wins leadership so a deploy does not trigger an instant fleet-wide
// read storm.
const (
	DefaultInterval     = 24 * time.Hour
	DefaultInitialDelay = time.Minute
	// perTenantPause paces the sweep so a fleet-wide collection spreads
	// its reads instead of issuing them in a tight loop.
	defaultPerTenantPause = 2 * time.Millisecond
)

// ControlResult is the evaluated posture of one control with its
// evidence reference, as surfaced to API callers and evidence packs.
type ControlResult struct {
	Control    Control
	Status     Status
	Summary    string
	Source     string
	ObservedAt time.Time
	Details    json.RawMessage
}

// FrameworkPosture is a tenant's posture for one framework.
type FrameworkPosture struct {
	Framework     Framework
	Total         int
	Pass          int
	Fail          int
	NotApplicable int
	Controls      []ControlResult
}

// TenantPosture is a tenant's complete posture across all frameworks.
type TenantPosture struct {
	TenantID    uuid.UUID
	GeneratedAt time.Time
	Frameworks  []FrameworkPosture
}

// Config tunes the engine. Zero values select sane defaults.
type Config struct {
	Interval     time.Duration
	InitialDelay time.Duration
	Clock        func() time.Time
	Logger       *slog.Logger
}

// Engine evaluates the control catalog against real platform state,
// persists results, and serves posture/evidence reads.
type Engine struct {
	source       PlatformSource
	repo         repository.ComplianceAutoRepository
	catalog      []Control
	clock        func() time.Time
	logger       *slog.Logger
	interval     time.Duration
	initialDelay time.Duration
	perTenant    time.Duration
}

// NewEngine wires the engine over a platform source and repository.
func NewEngine(source PlatformSource, repo repository.ComplianceAutoRepository, cfg Config) *Engine {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	initialDelay := cfg.InitialDelay
	if initialDelay <= 0 {
		initialDelay = DefaultInitialDelay
	}
	return &Engine{
		source:       source,
		repo:         repo,
		catalog:      catalog,
		clock:        clock,
		logger:       logger,
		interval:     interval,
		initialDelay: initialDelay,
		perTenant:    defaultPerTenantPause,
	}
}

// Evaluate reads the tenant's current platform state, computes every
// control's status with evidence, persists the run + per-control status +
// evidence history + per-framework rollup, and returns the freshly
// computed posture.
func (e *Engine) Evaluate(ctx context.Context, tenantID uuid.UUID) (TenantPosture, error) {
	startedAt := e.clock().UTC()
	snap, err := e.source.Snapshot(ctx, tenantID)
	if err != nil {
		return TenantPosture{}, fmt.Errorf("snapshot tenant %s: %w", tenantID, err)
	}

	results := make([]evaluatedControl, 0, len(e.catalog))
	var total, pass, fail, na int
	for _, ctrl := range e.catalog {
		collector, ok := CollectorFor(ctrl.CollectorID)
		if !ok {
			return TenantPosture{}, fmt.Errorf("control %s references unknown collector %q", ctrl.ID, ctrl.CollectorID)
		}
		obs := collector(snap)
		details, err := json.Marshal(obs.Details)
		if err != nil {
			return TenantPosture{}, fmt.Errorf("marshal evidence for control %s: %w", ctrl.ID, err)
		}
		results = append(results, evaluatedControl{control: ctrl, obs: obs, details: details})
		total++
		switch obs.Status {
		case StatusPass:
			pass++
		case StatusFail:
			fail++
		case StatusNotApplicable:
			na++
		}
	}

	finishedAt := e.clock().UTC()
	run, err := e.repo.RecordRun(ctx, tenantID, repository.ComplianceAutoRunRow{
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		ControlsTotal: total,
		ControlsPass:  pass,
		ControlsFail:  fail,
		ControlsNA:    na,
	})
	if err != nil {
		return TenantPosture{}, fmt.Errorf("record run: %w", err)
	}

	for _, r := range results {
		if _, err := e.repo.UpsertControlStatus(ctx, tenantID, repository.ComplianceAutoControlStatusRow{
			Framework:   string(r.control.Framework),
			ControlID:   r.control.ID,
			Status:      string(r.obs.Status),
			CollectorID: string(r.control.CollectorID),
			Summary:     r.obs.Summary,
			Source:      r.obs.Source,
			Details:     r.details,
			ObservedAt:  r.obs.ObservedAt,
			RunID:       run.ID,
		}); err != nil {
			return TenantPosture{}, fmt.Errorf("upsert control status %s: %w", r.control.ID, err)
		}
		if _, err := e.repo.AppendEvidence(ctx, tenantID, repository.ComplianceAutoEvidenceRow{
			RunID:       run.ID,
			Framework:   string(r.control.Framework),
			ControlID:   r.control.ID,
			CollectorID: string(r.control.CollectorID),
			Status:      string(r.obs.Status),
			Summary:     r.obs.Summary,
			Source:      r.obs.Source,
			Details:     r.details,
			ObservedAt:  r.obs.ObservedAt,
		}); err != nil {
			return TenantPosture{}, fmt.Errorf("append evidence %s: %w", r.control.ID, err)
		}
	}

	// Per-framework rollups.
	for _, fw := range Frameworks() {
		var ft, fp, ff, fna int
		for _, r := range results {
			if r.control.Framework != fw {
				continue
			}
			ft++
			switch r.obs.Status {
			case StatusPass:
				fp++
			case StatusFail:
				ff++
			case StatusNotApplicable:
				fna++
			}
		}
		if ft == 0 {
			continue
		}
		if _, err := e.repo.UpsertFrameworkState(ctx, tenantID, repository.ComplianceAutoFrameworkStateRow{
			Framework:     string(fw),
			ControlsTotal: ft,
			ControlsPass:  fp,
			ControlsFail:  ff,
			ControlsNA:    fna,
			LastRunID:     run.ID,
			EvaluatedAt:   finishedAt,
		}); err != nil {
			return TenantPosture{}, fmt.Errorf("upsert framework state %s: %w", fw, err)
		}
	}

	return e.buildPostureFromResults(tenantID, finishedAt, results), nil
}

// evaluatedControl pairs a catalog control with its computed observation
// and serialized evidence for a single sweep.
type evaluatedControl struct {
	control Control
	obs     Observation
	details json.RawMessage
}

// buildPostureFromResults assembles a TenantPosture from freshly
// evaluated results without an extra read.
func (e *Engine) buildPostureFromResults(tenantID uuid.UUID, at time.Time, results []evaluatedControl) TenantPosture {
	byFramework := map[Framework]*FrameworkPosture{}
	var order []Framework
	for _, r := range results {
		fp, ok := byFramework[r.control.Framework]
		if !ok {
			fp = &FrameworkPosture{Framework: r.control.Framework}
			byFramework[r.control.Framework] = fp
			order = append(order, r.control.Framework)
		}
		fp.Total++
		switch r.obs.Status {
		case StatusPass:
			fp.Pass++
		case StatusFail:
			fp.Fail++
		case StatusNotApplicable:
			fp.NotApplicable++
		}
		fp.Controls = append(fp.Controls, ControlResult{
			Control:    r.control,
			Status:     r.obs.Status,
			Summary:    r.obs.Summary,
			Source:     r.obs.Source,
			ObservedAt: r.obs.ObservedAt,
			Details:    r.details,
		})
	}
	posture := TenantPosture{TenantID: tenantID, GeneratedAt: at}
	for _, fw := range order {
		posture.Frameworks = append(posture.Frameworks, *byFramework[fw])
	}
	return posture
}

// Posture returns a tenant's stored posture. An empty framework returns
// every framework; a non-empty framework filters to it. Metadata
// (title/statement/category) is joined from the catalog by control id.
func (e *Engine) Posture(ctx context.Context, tenantID uuid.UUID, framework Framework) (TenantPosture, error) {
	rows, err := e.repo.ListControlStatus(ctx, tenantID, string(framework))
	if err != nil {
		return TenantPosture{}, err
	}
	index := catalogIndex()
	byFramework := map[Framework]*FrameworkPosture{}
	var order []Framework
	var newest time.Time
	for _, row := range rows {
		fw := Framework(row.Framework)
		fp, ok := byFramework[fw]
		if !ok {
			fp = &FrameworkPosture{Framework: fw}
			byFramework[fw] = fp
			order = append(order, fw)
		}
		ctrl, ok := index[controlKey{framework: fw, id: row.ControlID}]
		if !ok {
			ctrl = Control{ID: row.ControlID, Framework: fw, CollectorID: CollectorID(row.CollectorID)}
		}
		status := Status(row.Status)
		fp.Total++
		switch status {
		case StatusPass:
			fp.Pass++
		case StatusFail:
			fp.Fail++
		case StatusNotApplicable:
			fp.NotApplicable++
		}
		fp.Controls = append(fp.Controls, ControlResult{
			Control:    ctrl,
			Status:     status,
			Summary:    row.Summary,
			Source:     row.Source,
			ObservedAt: row.ObservedAt,
			Details:    row.Details,
		})
		if row.ObservedAt.After(newest) {
			newest = row.ObservedAt
		}
	}
	posture := TenantPosture{TenantID: tenantID, GeneratedAt: newest}
	for _, fw := range order {
		posture.Frameworks = append(posture.Frameworks, *byFramework[fw])
	}
	return posture, nil
}

// CollectAll evaluates every tenant in one bounded sweep. A per-tenant
// failure is logged and skipped so one bad tenant never aborts the
// fleet-wide collection. It returns an error only when tenant
// enumeration itself fails.
func (e *Engine) CollectAll(ctx context.Context) error {
	tenants, err := e.source.Tenants(ctx)
	if err != nil {
		return fmt.Errorf("enumerate tenants: %w", err)
	}
	var evaluated, failed int
	for _, tenantID := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := e.Evaluate(ctx, tenantID); err != nil {
			failed++
			e.logger.WarnContext(ctx, "complianceauto: tenant evaluation failed",
				"tenant_id", tenantID, "error", err)
		} else {
			evaluated++
		}
		if e.perTenant > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(e.perTenant):
			}
		}
	}
	e.logger.InfoContext(ctx, "complianceauto: sweep complete",
		"tenants", len(tenants), "evaluated", evaluated, "failed", failed)
	return nil
}

// Run is the leader-gated scheduler loop. It blocks until ctx is
// cancelled, running an initial sweep after initialDelay and then one
// sweep per interval. Its signature matches LeaderElector.RunIfLeader.
func (e *Engine) Run(ctx context.Context) {
	e.logger.InfoContext(ctx, "complianceauto: scheduler started",
		"interval", e.interval, "initial_delay", e.initialDelay)
	timer := time.NewTimer(e.initialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := e.CollectAll(ctx); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				e.logger.ErrorContext(ctx, "complianceauto: sweep failed", "error", err)
			}
			timer.Reset(e.interval)
		}
	}
}

// ExportPack builds an on-demand evidence pack for a tenant and
// framework from stored posture.
func (e *Engine) ExportPack(ctx context.Context, tenantID uuid.UUID, framework Framework) (EvidencePack, error) {
	posture, err := e.Posture(ctx, tenantID, framework)
	if err != nil {
		return EvidencePack{}, err
	}
	return BuildPack(posture, framework)
}

// controlKey indexes the catalog by (framework, control id).
type controlKey struct {
	framework Framework
	id        string
}

func catalogIndex() map[controlKey]Control {
	index := make(map[controlKey]Control, len(catalog))
	for _, c := range catalog {
		index[controlKey{framework: c.Framework, id: c.ID}] = c
	}
	return index
}
