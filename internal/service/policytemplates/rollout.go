package policytemplates

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"
)

// This file adds the cross-tenant roll-out surface on top of the
// per-tenant Apply path: render a baseline once and push it to N
// tenants in a single operator action, with a per-tenant diff preview
// beforehand and a per-tenant result (with rollback of any tenant whose
// apply fails) afterwards.
//
// No new persistence is involved: a roll-out is synchronous and reuses
// the existing tenant_policy_templates row (one applied baseline per
// tenant). Each tenant's UpsertApplied is its own atomic write, so the
// fan-out is per-tenant isolated — one failing tenant neither blocks
// the rest nor leaves a half-applied fleet.

// RolloutAction classifies, for a single tenant, what applying the
// target baseline would do relative to that tenant's current baseline.
type RolloutAction string

const (
	// RolloutActionCreate — the tenant has no baseline yet; the
	// roll-out would apply its first one.
	RolloutActionCreate RolloutAction = "create"
	// RolloutActionUpdate — the tenant has a baseline that differs
	// from the target; the roll-out would replace it.
	RolloutActionUpdate RolloutAction = "update"
	// RolloutActionNoop — the tenant already has this exact baseline
	// (same graph hash); the roll-out would be a no-op write.
	RolloutActionNoop RolloutAction = "noop"
)

// AppliedSummary is the compact, graph-free projection of a tenant's
// current baseline used in a roll-out preview. The full rendered graph
// is intentionally omitted: a preview lists many tenants and the diff
// the operator cares about is the selection + hash, not the bytes.
type AppliedSummary struct {
	Industry    string   `json:"industry"`
	Country     string   `json:"country"`
	Regime      string   `json:"regime"`
	TemplateIDs []string `json:"template_ids"`
	GraphHash   string   `json:"graph_hash"`
	Version     int      `json:"version"`
}

// RolloutTargetDiff is the per-tenant entry of a roll-out preview: the
// action the roll-out would take and the tenant's current baseline (nil
// when the tenant has none).
type RolloutTargetDiff struct {
	TenantID uuid.UUID       `json:"tenant_id"`
	Action   RolloutAction   `json:"action"`
	Current  *AppliedSummary `json:"current,omitempty"`
}

// RolloutPreview is the dry-run of a cross-tenant roll-out: the target
// baseline (rendered once) plus the per-tenant diff for every selected
// tenant. It performs no writes.
type RolloutPreview struct {
	Selection   Selection           `json:"selection"`
	Regime      ComplianceRegime    `json:"regime"`
	TemplateIDs []string            `json:"template_ids"`
	GraphHash   string              `json:"graph_hash"`
	Targets     []RolloutTargetDiff `json:"targets"`
}

// RolloutStatus is the per-tenant result of an executed roll-out.
type RolloutStatus string

const (
	// RolloutStatusApplied — the target baseline was written for the
	// tenant (a create or an update).
	RolloutStatusApplied RolloutStatus = "applied"
	// RolloutStatusUnchanged — the tenant already had this exact
	// baseline, so no write occurred.
	RolloutStatusUnchanged RolloutStatus = "unchanged"
	// RolloutStatusFailed — the apply errored for this tenant. See
	// RolledBack for whether the tenant's prior baseline was preserved.
	RolloutStatusFailed RolloutStatus = "failed"
)

// RolloutOutcome is the per-tenant result of an executed roll-out.
type RolloutOutcome struct {
	TenantID uuid.UUID     `json:"tenant_id"`
	Status   RolloutStatus `json:"status"`
	// PriorHash is the tenant's baseline hash before the roll-out
	// (empty when the tenant had none).
	PriorHash string `json:"prior_hash,omitempty"`
	// GraphHash is the tenant's baseline hash after a successful apply
	// (empty on failure).
	GraphHash string `json:"graph_hash,omitempty"`
	// RolledBack is set on a failed tenant whose prior baseline was
	// restored (or never touched), i.e. the tenant is guaranteed not to
	// be left in a partially-applied state. It is false for a failed
	// tenant that had no prior baseline (nothing to roll back to).
	RolledBack bool `json:"rolled_back,omitempty"`
	// Error is the failure message (empty on success).
	Error string `json:"error,omitempty"`
}

// RolloutResult is the outcome of an executed cross-tenant roll-out:
// the target baseline plus a per-tenant result and roll-up counts.
type RolloutResult struct {
	Selection   Selection        `json:"selection"`
	Regime      ComplianceRegime `json:"regime"`
	TemplateIDs []string         `json:"template_ids"`
	GraphHash   string           `json:"graph_hash"`
	Outcomes    []RolloutOutcome `json:"outcomes"`
	Applied     int              `json:"applied"`
	Unchanged   int              `json:"unchanged"`
	Failed      int              `json:"failed"`
}

// dedupeTenants validates and de-duplicates a roll-out target list,
// preserving first-seen order. An empty list or any nil UUID is a
// client error.
func dedupeTenants(tenantIDs []uuid.UUID) ([]uuid.UUID, error) {
	if len(tenantIDs) == 0 {
		return nil, fmt.Errorf("at least one tenant id is required: %w", errInvalidArgument)
	}
	seen := make(map[uuid.UUID]struct{}, len(tenantIDs))
	out := make([]uuid.UUID, 0, len(tenantIDs))
	for _, id := range tenantIDs {
		if id == uuid.Nil {
			return nil, fmt.Errorf("tenant id required: %w", errInvalidArgument)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// summarize projects a stored baseline into its preview-facing summary.
func summarize(a AppliedTemplate) AppliedSummary {
	return AppliedSummary{
		Industry:    a.Industry,
		Country:     a.Country,
		Regime:      a.Regime,
		TemplateIDs: a.TemplateIDs,
		GraphHash:   a.GraphHash,
		Version:     a.Version,
	}
}

// PreviewRollout renders the baseline for sel once and computes, for
// each selected tenant, the diff against that tenant's current
// baseline. It performs no writes and is safe to call repeatedly.
func (s *Service) PreviewRollout(ctx context.Context, tenantIDs []uuid.UUID, sel Selection) (RolloutPreview, error) {
	if s.repo == nil {
		return RolloutPreview{}, ErrRepositoryUnavailable
	}
	tids, err := dedupeTenants(tenantIDs)
	if err != nil {
		return RolloutPreview{}, err
	}
	resolved, err := Resolve(sel)
	if err != nil {
		return RolloutPreview{}, err
	}

	targets := make([]RolloutTargetDiff, 0, len(tids))
	for _, tid := range tids {
		diff := RolloutTargetDiff{TenantID: tid, Action: RolloutActionCreate}
		current, gerr := s.repo.GetApplied(ctx, tid)
		switch {
		case gerr == nil:
			summary := summarize(current)
			diff.Current = &summary
			if current.GraphHash == resolved.GraphHash {
				diff.Action = RolloutActionNoop
			} else {
				diff.Action = RolloutActionUpdate
			}
		case isNotFound(gerr):
			// No baseline yet — create.
		default:
			return RolloutPreview{}, gerr
		}
		targets = append(targets, diff)
	}

	return RolloutPreview{
		Selection:   resolved.Selection,
		Regime:      resolved.Regime,
		TemplateIDs: resolved.TemplateIDs,
		GraphHash:   resolved.GraphHash,
		Targets:     targets,
	}, nil
}

// ExecuteRollout applies the baseline for sel to every selected tenant,
// returning a per-tenant result. Each tenant is processed independently
// and atomically: a tenant whose apply fails is rolled back to its
// prior baseline (or left without one if it had none), and does not
// abort the rest of the fan-out. Re-applying a tenant's existing
// baseline is reported as unchanged with no write.
func (s *Service) ExecuteRollout(ctx context.Context, tenantIDs []uuid.UUID, sel Selection) (RolloutResult, error) {
	if s.repo == nil {
		return RolloutResult{}, ErrRepositoryUnavailable
	}
	tids, err := dedupeTenants(tenantIDs)
	if err != nil {
		return RolloutResult{}, err
	}
	resolved, err := Resolve(sel)
	if err != nil {
		return RolloutResult{}, err
	}

	result := RolloutResult{
		Selection:   resolved.Selection,
		Regime:      resolved.Regime,
		TemplateIDs: resolved.TemplateIDs,
		GraphHash:   resolved.GraphHash,
		Outcomes:    make([]RolloutOutcome, 0, len(tids)),
	}

	for _, tid := range tids {
		outcome := s.rolloutOne(ctx, tid, resolved)
		switch outcome.Status {
		case RolloutStatusApplied:
			result.Applied++
		case RolloutStatusUnchanged:
			result.Unchanged++
		case RolloutStatusFailed:
			result.Failed++
		}
		result.Outcomes = append(result.Outcomes, outcome)
	}
	return result, nil
}

// rolloutOne applies resolved to a single tenant, capturing its prior
// baseline so a failed write can be rolled back. It never returns an
// error: every failure is reported in the RolloutOutcome so one bad
// tenant cannot abort the fan-out.
func (s *Service) rolloutOne(ctx context.Context, tenantID uuid.UUID, resolved Resolved) RolloutOutcome {
	prior, gerr := s.repo.GetApplied(ctx, tenantID)
	priorExists := gerr == nil
	if gerr != nil && !isNotFound(gerr) {
		return RolloutOutcome{TenantID: tenantID, Status: RolloutStatusFailed, Error: gerr.Error()}
	}
	priorHash := ""
	if priorExists {
		priorHash = prior.GraphHash
	}

	// Idempotent no-op: the tenant already has this exact baseline.
	if priorExists && priorHash == resolved.GraphHash {
		return RolloutOutcome{
			TenantID:  tenantID,
			Status:    RolloutStatusUnchanged,
			PriorHash: priorHash,
			GraphHash: resolved.GraphHash,
		}
	}

	stored, aerr := s.repo.UpsertApplied(ctx, appliedFromResolved(tenantID, resolved))
	if aerr != nil {
		// Roll back: restore the prior baseline if one existed so the
		// tenant is never left in a partially-applied state. A tenant
		// with no prior baseline simply has none — also a clean state.
		rolledBack := !priorExists
		if priorExists {
			if _, rerr := s.repo.UpsertApplied(ctx, prior); rerr == nil {
				rolledBack = true
			}
		}
		return RolloutOutcome{
			TenantID:   tenantID,
			Status:     RolloutStatusFailed,
			PriorHash:  priorHash,
			RolledBack: rolledBack,
			Error:      aerr.Error(),
		}
	}

	s.logger.InfoContext(ctx, "rolled out policy template baseline",
		"tenant_id", tenantID.String(),
		"industry", stored.Industry,
		"country", stored.Country,
		"regime", stored.Regime,
		"graph_hash", stored.GraphHash,
	)
	return RolloutOutcome{
		TenantID:  tenantID,
		Status:    RolloutStatusApplied,
		PriorHash: priorHash,
		GraphHash: stored.GraphHash,
	}
}

// SelectionOption vocabularies -------------------------------------------

// IndustryOption is a selectable industry plus its human-facing catalog
// name and template id. Sourced from the immutable catalog.
type IndustryOption struct {
	Industry   Industry `json:"industry"`
	Name       string   `json:"name"`
	TemplateID string   `json:"template_id"`
}

// CountryOption is a selectable country code and the compliance regime
// it resolves to.
type CountryOption struct {
	Country Country          `json:"country"`
	Regime  ComplianceRegime `json:"regime"`
}

// SelectionOptions is the closed vocabulary the operator picks a
// Selection from: every modelled industry and every supported country
// (with the regime each maps to). It powers the roll-out picker and the
// onboarding wizard's selection step so the console never offers a
// combination the renderer would reject.
type SelectionOptions struct {
	Industries []IndustryOption `json:"industries"`
	Countries  []CountryOption  `json:"countries"`
}

// SelectionOptions returns the catalog's industries and the supported
// countries (each with its compliance regime), both sorted for a stable
// wire order.
func (s *Service) SelectionOptions() SelectionOptions {
	industries := make([]IndustryOption, 0)
	for _, t := range s.catalog {
		if t.Kind != KindIndustry {
			continue
		}
		industries = append(industries, IndustryOption{
			Industry:   t.Industry,
			Name:       t.Name,
			TemplateID: t.ID,
		})
	}
	sort.Slice(industries, func(i, j int) bool {
		return industries[i].Industry < industries[j].Industry
	})

	countries := make([]CountryOption, 0, len(countryRegimes))
	for c, r := range countryRegimes {
		countries = append(countries, CountryOption{Country: c, Regime: r})
	}
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Country < countries[j].Country
	})

	return SelectionOptions{Industries: industries, Countries: countries}
}

// appliedFromResolved builds the persistence DTO for a tenant from a
// rendered baseline. Shared by Apply and the roll-out path so the two
// produce byte-identical stored rows.
func appliedFromResolved(tenantID uuid.UUID, resolved Resolved) AppliedTemplate {
	return AppliedTemplate{
		TenantID:    tenantID,
		Industry:    string(resolved.Selection.Industry),
		Country:     string(resolved.Selection.Country),
		Regime:      string(resolved.Regime),
		TemplateIDs: resolved.TemplateIDs,
		GraphHash:   resolved.GraphHash,
		Graph:       resolved.GraphJSON,
		Version:     GraphVersion,
	}
}
