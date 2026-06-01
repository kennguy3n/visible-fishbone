// Package policy — dryrun.go implements shadow-bundle compilation
// (Phase 3 Block 2, Task 8).
//
// A "dry-run" bundle is a normal, signed PolicyBundle compiled
// from a PROPOSED graph that is NOT (yet) the tenant's canonical
// graph. Agents that receive a dry-run bundle log the verdicts it
// produces but DO NOT enforce them — the live bundle continues
// to govern actual traffic. The operator inspects the delta
// between the live verdict stream and the dry-run verdict stream
// to decide whether the proposed graph is safe to promote.
//
// The shadow bundle is wire-identical to a live bundle except for
// two fields:
//
//   - bundle_kind = "dry_run" (string) so the agent can
//     differentiate at unpack time and skip enforcement.
//   - subject       = the dry-run NATS subject (string) so the
//     agent's reporting pipeline forks shadow verdicts onto a
//     distinct stream from the live verdicts.
//
// The signing path is identical to the live bundle so an agent
// that already verifies bundle signatures cannot be tricked into
// honouring an unsigned shadow.
//
// Subject routing per ARCHITECTURE.md §6 (NATS subject taxonomy):
//
//   live   verdicts -> sng.<tenant>.telemetry.verdict
//   shadow verdicts -> sng.<tenant>.telemetry.verdict.dryrun.<simulation_id>
//
// The simulation_id binds the shadow stream to a specific
// proposed-graph compilation; an operator running two overlapping
// dry-runs (e.g. comparing two proposals against the same fleet)
// distinguishes them by simulation_id.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Errors surfaced by the dry-run compiler.
var (
	// ErrDryRunSignerRequired is returned when CompileDryRun is
	// called on a Service constructed without a signer. The
	// shadow bundle must be signed so receivers can verify it
	// the same way they verify the live bundle.
	ErrDryRunSignerRequired = errors.New("policy: dryrun compile requires a signer")
)

// DryRunSubject returns the canonical NATS subject for a
// dry-run verdict stream scoped to (tenant, simulationID). The
// stream taxonomy is documented in ARCHITECTURE.md §6.
//
// Agents subscribe to the live subject and PUBLISH shadow
// verdicts onto the dry-run subject; the simulator (or the
// operator-facing UI) consumes the dry-run subject to render the
// "what changed under the proposed graph" view.
//
// The function is pure — it does not touch NATS, and exists at
// package scope so the handler can render the subject into the
// operator-facing dry-run response without depending on a
// Service instance.
func DryRunSubject(tenantID, simulationID uuid.UUID) string {
	return fmt.Sprintf("sng.%s.telemetry.verdict.dryrun.%s",
		tenantID.String(), simulationID.String())
}

// DryRunOptions tunes one CompileDryRun call. All fields are
// optional.
type DryRunOptions struct {
	// SimulationID identifies the dry-run for subject routing
	// and audit. Zero -> the compiler generates a fresh UUID.
	// Pass an existing ID when extending a simulator-produced
	// ImpactReport into a dry-run rollout.
	SimulationID uuid.UUID

	// Targets restricts compilation to a subset of the canonical
	// 4-target list. Empty -> compile for every target. Used by
	// the canary controller when an operator scopes the dry-run
	// to e.g. only edge bundles.
	Targets []repository.PolicyBundleTarget
}

// DryRunResult is the output of CompileDryRun. It mirrors
// CompileResult but the bundles carry the dry-run marker (the
// bundle bytes themselves encode bundle_kind=dry_run so receivers
// see it at unpack time) and the bundles are NOT persisted — a
// dry-run is by definition ephemeral, valid only for the
// duration of the operator's review.
type DryRunResult struct {
	// SimulationID echoes the input (or the one the compiler
	// generated when the input was zero).
	SimulationID uuid.UUID

	// GraphID is the proposed graph the dry-run was compiled
	// from.
	GraphID uuid.UUID

	// Subject is the NATS subject agents will publish shadow
	// verdicts onto.
	Subject string

	// Bundles are the signed shadow bundles, one per target in
	// the canonical order. Returned IN-MEMORY only — the
	// dry-run path does NOT persist to the policy_bundles
	// table because that table is the source of truth for the
	// live bundle stream and we don't want shadow rows polluting
	// it. The caller distributes the bytes via the agent-push
	// channel (NATS) directly.
	Bundles []repository.PolicyBundle

	// Targets is the ordered list of targets compiled.
	Targets []repository.PolicyBundleTarget

	// Compiled is the wall-clock timestamp baked into every
	// shadow bundle's compiled_at field. Pinned by Service's
	// clock so determinism holds across replays.
	Compiled time.Time
}

// CompileDryRun produces signed shadow bundles for the given
// PROPOSED graph without persisting them and without disturbing
// the tenant's live policy. The result's Bundles field is
// ready for direct push onto the dry-run NATS subject.
//
// The proposed graph need not be (and typically isn't) the
// tenant's current canonical graph; it's the operator's
// candidate next-version. The caller is responsible for having
// validated the graph schema (typically by routing through
// PutGraph on a separate "draft" tenant or by a dedicated
// validate-only endpoint).
func (s *Service) CompileDryRun(
	ctx context.Context,
	tenantID uuid.UUID,
	proposed repository.PolicyGraph,
	opts DryRunOptions,
) (DryRunResult, error) {
	if s.signer == nil {
		return DryRunResult{}, ErrDryRunSignerRequired
	}
	if tenantID == uuid.Nil {
		return DryRunResult{}, errors.New("policy: dryrun tenant id required")
	}
	if proposed.ID == uuid.Nil || len(proposed.Graph) == 0 {
		return DryRunResult{}, errors.New("policy: dryrun proposed graph required")
	}

	simulationID := opts.SimulationID
	if simulationID == uuid.Nil {
		simulationID = uuid.New()
	}

	targets := opts.Targets
	if len(targets) == 0 {
		targets = append([]repository.PolicyBundleTarget(nil), allTargets...)
	} else {
		for _, t := range targets {
			if !isValidTarget(t) {
				return DryRunResult{}, fmt.Errorf("policy: dryrun unsupported target %q", t)
			}
		}
	}

	// EnsureKey on the live path is a no-op for ephemeral
	// signers; we do the same call here so a dry-run with a
	// fresh tenant (which has no active key yet) provisions one
	// before signing.
	if ensurer, ok := s.signer.(KeyEnsurer); ok {
		if err := ensurer.EnsureKey(ctx, tenantID); err != nil {
			return DryRunResult{}, fmt.Errorf("ensure signing key: %w", err)
		}
	}

	compiledAt := time.Now().UTC()
	var prepared PreparedSigning
	if ps, ok := s.signer.(PreparedSigner); ok {
		var err error
		prepared, err = ps.PrepareSigner(ctx, tenantID)
		if err != nil {
			return DryRunResult{}, fmt.Errorf("prepare signer: %w", err)
		}
	}

	var typed *Graph
	if parsed, err := ParseGraph(proposed.Graph); err == nil {
		typed = &parsed
	} else {
		// Same fallback behaviour as Compile — log so the
		// operator sees they're on the legacy verbatim-rules
		// path. Dry-runs always log here at warn because by
		// definition the operator is iterating on the graph
		// shape and benefits from the visibility.
		s.logger.Warn("policy.dryrun: typed-graph parse failed; falling back to verbatim-rules path (per-target rule slicing disabled)",
			slog.String("tenant_id", tenantID.String()),
			slog.String("graph_id", proposed.ID.String()),
			slog.String("simulation_id", simulationID.String()),
			slog.Any("error", err),
		)
	}

	subject := DryRunSubject(tenantID, simulationID)
	bundles := make([]repository.PolicyBundle, 0, len(targets))
	for _, target := range targets {
		payload, err := encodeDryRunBundle(target, proposed, typed, simulationID, subject, compiledAt)
		if err != nil {
			return DryRunResult{}, fmt.Errorf("encode dryrun %s: %w", target, err)
		}
		var (
			sig   []byte
			keyID string
		)
		if prepared != nil {
			sig, keyID = prepared.Sign(payload)
		} else {
			sig, keyID, err = s.signer.Sign(ctx, tenantID, payload)
			if err != nil {
				return DryRunResult{}, fmt.Errorf("sign dryrun %s: %w", target, err)
			}
		}
		bundles = append(bundles, repository.PolicyBundle{
			// ID stays zero — these are in-memory only.
			PolicyGraphID: proposed.ID,
			TargetType:    target,
			Bundle:        payload,
			Signature:     sig,
			KeyID:         keyID,
			CreatedAt:     compiledAt,
		})
	}

	if s.audit != nil {
		details, _ := json.Marshal(map[string]any{
			"graph_id":      proposed.ID,
			"graph_version": proposed.Version,
			"simulation_id": simulationID,
			"targets":       targets,
			"subject":       subject,
			"kind":          "dry_run",
		})
		_, _ = s.audit.Append(ctx, tenantID, repository.AuditEntry{
			TenantID: tenantID,
			Action:   "policy.dryrun_compiled", ResourceType: "policy_graph",
			ResourceID: &proposed.ID, Details: details,
		})
	}

	return DryRunResult{
		SimulationID: simulationID,
		GraphID:      proposed.ID,
		Subject:      subject,
		Bundles:      bundles,
		Targets:      targets,
		Compiled:     compiledAt,
	}, nil
}

// dryRunBundlePayload is the shadow-bundle wire shape. It
// extends bundlePayload with two fields:
//
//   - Kind = "dry_run" so agents that unpack the envelope can
//     branch at the verifier without inspecting the subject.
//   - Subject — the NATS subject agents publish shadow verdicts
//     onto. Stamped into the bundle (rather than left to
//     out-of-band config) so the receiver cannot accidentally
//     publish dry-run verdicts onto the live verdict stream.
type dryRunBundlePayload struct {
	SchemaVersion uint8           `msgpack:"v"`
	Target        string          `msgpack:"t"`
	GraphID       string          `msgpack:"g"`
	GraphVersion  int             `msgpack:"gv"`
	Compiler      string          `msgpack:"c"`
	DefaultAction string          `msgpack:"d"`
	Rules         json.RawMessage `msgpack:"r"`
	Steering      json.RawMessage `msgpack:"st,omitempty"`
	CompiledAt    string          `msgpack:"ts"`
	Kind          string          `msgpack:"k"`
	SimulationID  string          `msgpack:"sim"`
	Subject       string          `msgpack:"sub"`
}

func encodeDryRunBundle(
	target repository.PolicyBundleTarget,
	g repository.PolicyGraph,
	typed *Graph,
	simulationID uuid.UUID,
	subject string,
	compiledAt time.Time,
) ([]byte, error) {
	rules, defaultAction := perTargetRulesFromParsed(target, g.Graph, typed)
	p := dryRunBundlePayload{
		SchemaVersion: 1,
		Target:        string(target),
		GraphID:       g.ID.String(),
		GraphVersion:  g.Version,
		Compiler:      CompilerVersion,
		DefaultAction: defaultAction,
		Rules:         rules,
		Steering:      nil, // dry-run focuses on enforcement; steering replay is a separate concern (Task 24).
		CompiledAt:    compiledAt.Format(time.RFC3339Nano),
		Kind:          "dry_run",
		SimulationID:  simulationID.String(),
		Subject:       subject,
	}
	return msgpack.Marshal(&p)
}
