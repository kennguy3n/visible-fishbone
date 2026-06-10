// Package policy contains the policy-graph service, compiler, and
// bundle store wrapper. PR6 introduces the service surface (graph
// get/put + a default-safe compiler that emits signed deny-all
// bundles for all four enforcement targets). PR7 adds the rich
// typed graph model and the per-target rule transformation logic.
package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// CompilerVersion is the version stamped into compiled bundles so
// the agent can refuse bundles produced by an incompatible compiler.
// Bump on any wire-format change.
const CompilerVersion = "sng-policy/0.1"

// Signer signs bundle bytes with a tenant's signing key. Implementations
// may use a software Ed25519 key (default) or an HSM. The interface
// allows PR8+ to swap in a hardware-backed signer without touching the
// service code.
//
// The returned KeyID identifies which tenant key produced the signature
// so receivers know which public key to verify against — see
// repository.PolicySigningKey.KeyID and the bundle envelope's `kid`
// field. PR6's EphemeralSigner returns an empty KeyID for back-compat;
// the PR7 KeyService-backed signer returns the active key's short id.
type Signer interface {
	Sign(ctx context.Context, tenantID uuid.UUID, data []byte) (signature []byte, keyID string, err error)
}

// KeyEnsurer is an optional extension of Signer that lets a signer
// pre-flight before a compile run — e.g. provisioning the very
// first key for a brand-new tenant so the per-target Sign loop
// doesn't fail on ErrNotFound. The PR7 KeyService implements this
// interface; EphemeralSigner / KeySigner do not (their key is
// loaded eagerly at construction).
//
// Compile type-asserts on this interface and skips the pre-flight
// when the signer doesn't provide it. EnsureKey MUST be idempotent
// and MUST NOT auto-provision when the tenant has had keys before
// but none are currently active (revocation-incident state).
type KeyEnsurer interface {
	EnsureKey(ctx context.Context, tenantID uuid.UUID) error
}

// SteeringCompiler produces the per-target traffic-classification
// steering rules that the policy compiler embeds into each bundle.
// The interface is satisfied by *appdb.Service via the adapter
// PolicySteeringAdapter — declared here as an interface so the
// policy package does not import appdb directly (preventing an
// import cycle and keeping the policy service unit-testable with a
// tiny fake).
//
// The return type is `any` rather than a typed struct so the
// interface stays decoupled from the appdb package; callers that
// need the typed shape can type-assert. The policy compiler only
// needs to JSON-encode the value, so a generic `any` is sufficient.
//
// SnapshotSteering returns a per-tenant cache of the catalog +
// overrides so the compiler can produce every per-target rule
// set from a single pair of DB reads instead of repeating those
// reads for every target. The returned snapshot is single-use:
// callers must not retain it across Compile invocations because
// the underlying catalog drifts as operators mutate the registry.
// A `nil` snapshot (no compiler installed) signals to the caller
// that the steering section should be omitted from the bundle.
type SteeringCompiler interface {
	CompileSteeringRules(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (any, error)
	// SnapshotSteering returns an object that implements
	// SteeringSnapshot. The return is typed as `any` for the
	// same reason CompileSteeringRules returns `any` — the
	// concrete type lives in appdb and this package cannot
	// import it. The Compile method type-asserts the result.
	SnapshotSteering(ctx context.Context, tenantID uuid.UUID) (any, error)
}

// SteeringSnapshot is the interface the policy compiler uses to
// produce per-target rules from a pre-fetched catalog. Implemented
// by appdb.PolicySteeringSnapshotAdapter (wrapping
// *appdb.SteeringSnapshot). Reusing the same snapshot across all
// targets in a single Compile call avoids the N × ListAll round
// trip pattern called out in Devin Review on commit 02765a2.
type SteeringSnapshot interface {
	CompileForTarget(target repository.PolicyBundleTarget) (any, error)
}

// InlineCASBCompiler produces a tenant's inline-CASB rules as
// policy.Rule entries (Domain == DomainInlineCASB) for the compiler
// to fold into the policy graph before per-target slicing. It is
// satisfied directly by *casb.InlineCASBService.CompileRules —
// declared as an interface here so the policy package does not
// import the casb service package (avoiding an import cycle and
// keeping Compile unit-testable with a tiny fake).
//
// Returned rules already carry their CASB payload in Extra["casb"]
// and route to the edge + cloud targets via domainTargets, exactly
// like a DomainSWG rule. A nil compiler (in-process tests, dry
// runs) leaves the inline-CASB section out of every bundle,
// matching the pre-inline-CASB behaviour.
type InlineCASBCompiler interface {
	CompileRules(ctx context.Context, tenantID uuid.UUID) ([]Rule, error)
}

// IOCCompiler produces the threat-intel deny rules for a tenant as
// policy.Rule entries, for the compiler to fold into the typed
// graph before per-target slicing — the same mechanism as
// InlineCASBCompiler. The rules carry the standard enforcement
// domains (DomainNGFW for IP IOCs, DomainDNS for domain IOCs,
// DomainSWG for URL IOCs) so they route to the right targets via
// domainTargets and ride the same per-target slicing, signing and
// versioning as every operator-authored rule.
//
// Threat-feed indicators are global (they apply to every tenant —
// see the demotion engine's threat_feed signal), so a typical
// implementation ignores tenantID and returns the same deny set
// for all tenants; the parameter is kept for symmetry and to allow
// a future per-tenant allow-list carve-out. A nil compiler leaves
// the threat-intel rules out of every bundle.
type IOCCompiler interface {
	CompileIOCRules(ctx context.Context, tenantID uuid.UUID) ([]Rule, error)
}

// MalwareHashCompiler produces the malicious file-hash verdicts a
// bundle ships to the SWG malware inspector (the StaticMalwareList
// in crates/sng-swg). Hash IOCs cannot be expressed as a graph
// rule — the SWG matches a response body's SHA-256 against an
// in-memory table, not a flow/DNS/HTTP predicate — so they ride a
// dedicated bundle section instead of the rule slice. The section
// is emitted only for targets that run the SWG ext-authz malware
// path (edge + cloud, matching domainTargets(DomainSWG)). A nil
// compiler omits the section, leaving the receiver's malware list
// empty (every hash resolves to Unknown).
type MalwareHashCompiler interface {
	CompileMalwareHashes(ctx context.Context, tenantID uuid.UUID) ([]MalwareHashEntry, error)
}

// IOCSnapshot is a single point-in-time view of the IOC store from
// which BOTH the threat-intel deny-rule slice and the malware-hash
// set are derived, so a concurrent feed refresh cannot make the two
// planes disagree within one compile. The IOC rules (IP/domain/URL
// denies) and the malware section take separate sub-views of the
// store; without a shared snapshot a feed update landing between the
// two compiler calls could put a hash in the malware section whose
// matching URL deny is absent from the rule slice (or vice versa).
// Single-use, mirroring SteeringSnapshot: callers must not retain it
// across compiles because the underlying store drifts as feeds
// refresh.
type IOCSnapshot interface {
	CompileIOCRules() ([]Rule, error)
	CompileMalwareHashes() ([]MalwareHashEntry, error)
}

// IOCSnapshotCompiler is the optional capability the policy compiler
// prefers when present: capture one store snapshot and derive both
// the rule slice and the malware set from it. Satisfied by the ai
// IOC enforcement compiler. When the installed IOCCompiler also
// implements this interface (and the malware compiler, if wired, is
// the same instance), Compile and CompileDryRun take a single
// snapshot per call instead of two independent ones. A compiler that
// does not implement it (e.g. a test fake wiring the two interfaces
// separately) falls back to the independent IOCCompiler /
// MalwareHashCompiler calls.
//
// The same-instance requirement is by identity (see sharedIOCSnapshot):
// a decorator (logging, metrics) that wraps only one of the two
// interfaces changes its dynamic type and disables the shared path,
// falling back to independent calls. To keep the optimisation while
// decorating, wrap a single value that implements IOCSnapshotCompiler
// and pass that same value to both WithIOCCompiler and
// WithMalwareHashCompiler.
type IOCSnapshotCompiler interface {
	SnapshotIOC(ctx context.Context, tenantID uuid.UUID) (IOCSnapshot, error)
}

// Service is the policy service.
type Service struct {
	repo        repository.PolicyRepository
	audit       repository.AuditLogRepository
	signer      Signer
	logger      *slog.Logger
	steering    SteeringCompiler
	inlineCASB  InlineCASBCompiler
	ioc         IOCCompiler
	malwareHash MalwareHashCompiler
}

// ServiceOption configures New.
type ServiceOption func(*Service)

// WithLogger installs a non-default slog.Logger. Defaults to
// slog.Default(). The logger is used today to surface the
// legacy-graph compile-time fallback (Devin Review #3312847384):
// when ParseGraph fails on a stored graph, Compile cannot do the
// per-target rule transformation and forwards the verbatim rules
// instead. That fallback is intentional for graphs written before
// the typed schema landed, but operators need a clear signal so
// the divergence isn't silent.
func WithLogger(l *slog.Logger) ServiceOption {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithSteeringCompiler installs the traffic-classification
// steering compiler. When supplied, Compile embeds the per-target
// steering rules into each bundle's `steering` field. When nil,
// bundles ship without a steering section (the receiver treats a
// missing section as "no classification — fall back to the
// pre-classification enforcement paths"). Production callers pass
// the *appdb.Service from cmd/sng-control.
func WithSteeringCompiler(c SteeringCompiler) ServiceOption {
	return func(s *Service) {
		s.steering = c
	}
}

// WithInlineCASBCompiler installs the inline-CASB rule compiler.
// When supplied, Compile merges the tenant's enabled inline-CASB
// rules into the typed graph before per-target slicing, so they
// ship in the edge + cloud bundles' rule slice. When nil, bundles
// carry no inline-CASB rules (the SWG inspector enforces nothing
// until rules are installed). Production callers pass the
// *casb.InlineCASBService from cmd/sng-control.
func WithInlineCASBCompiler(c InlineCASBCompiler) ServiceOption {
	return func(s *Service) {
		s.inlineCASB = c
	}
}

// WithIOCCompiler installs the threat-intel IOC rule compiler.
// When supplied, Compile folds the current threat-feed deny rules
// (IP -> NGFW deny, domain -> DNS deny/sinkhole, URL -> SWG deny)
// into the typed graph before per-target slicing, so they ship in
// the relevant target bundles. When nil, bundles carry no
// threat-intel rules. Production callers pass the IOC enforcement
// compiler built over the feed aggregator's IOCStore.
func WithIOCCompiler(c IOCCompiler) ServiceOption {
	return func(s *Service) {
		s.ioc = c
	}
}

// WithMalwareHashCompiler installs the malware file-hash compiler.
// When supplied, Compile embeds the current malicious-hash set into
// the edge + cloud bundles' malware section, which the SWG malware
// inspector installs into its StaticMalwareList. When nil, the
// section is omitted.
func WithMalwareHashCompiler(c MalwareHashCompiler) ServiceOption {
	return func(s *Service) {
		s.malwareHash = c
	}
}

// New returns a ready-to-use policy service.
func New(repo repository.PolicyRepository, audit repository.AuditLogRepository, signer Signer, opts ...ServiceOption) *Service {
	s := &Service{repo: repo, audit: audit, signer: signer, logger: slog.Default()}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GraphInput is the JSON-serialized graph the operator submits.
// PR6 treats it opaquely (stored as JSON, copied into every bundle);
// PR7 will introduce a typed Graph struct.
type GraphInput struct {
	Version       int             `json:"version,omitempty"`
	DefaultAction string          `json:"default_action,omitempty"`
	Rules         json.RawMessage `json:"rules,omitempty"`
	// Raw allows callers to pass arbitrary additional fields that
	// PR7+ will interpret. Stored verbatim.
	Raw map[string]json.RawMessage `json:"-"`
}

// GetCurrentGraph returns the most recent graph for the tenant.
func (s *Service) GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (repository.PolicyGraph, error) {
	return s.repo.GetCurrentGraph(ctx, tenantID)
}

// PolicyCounts reports the tenant's current published policy-rule
// totals: the total number of rules and the subset that is actively
// enforcing. "Active" excludes suggest_only rules, which are
// proposed-but-not-enforcing (e.g. AI-suggested deltas awaiting
// operator approval) — these are exactly the "dormant" policies the
// dashboard prompts operators to activate.
//
// Returns (0, 0, nil) when the tenant has no published graph yet so
// callers render an honest empty coverage state rather than an error.
//
// A stored graph that fails the typed-schema parse (a legacy graph
// written before PutGraph validated against the typed schema) does not
// fail the call: it mirrors Compile's verbatim-rules fallback (Devin
// Review #3312847384) by counting the raw `rules` array and logging a
// warning, so the dashboard's coverage meter keeps working for those
// tenants exactly as Compile keeps producing bundles for them. Only a
// genuinely unparseable graph (not even valid JSON with a rules array)
// yields the honest 0/0 empty state.
func (s *Service) PolicyCounts(ctx context.Context, tenantID uuid.UUID) (total, active int, err error) {
	pg, err := s.repo.GetCurrentGraph(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	rules, ok := s.countableRules(tenantID, pg)
	if !ok {
		return 0, 0, nil
	}
	for _, v := range rules {
		total++
		if v != VerbSuggestOnly {
			active++
		}
	}
	return total, active, nil
}

// countableRules returns the verbs of the graph's rules for coverage
// counting. It prefers the typed parse; on a typed-schema parse failure
// it falls back to a lightweight decode of the verbatim `rules` array
// (mirroring Compile's legacy-graph path) and logs a warning. ok is
// false only when the graph can't be decoded at all, in which case the
// caller reports an honest 0/0 rather than an error.
func (s *Service) countableRules(tenantID uuid.UUID, pg repository.PolicyGraph) (verbs []Verb, ok bool) {
	g, perr := ParseGraph(pg.Graph)
	if perr == nil {
		verbs = make([]Verb, 0, len(g.Rules))
		for _, r := range g.Rules {
			verbs = append(verbs, r.Verb)
		}
		return verbs, true
	}

	// Typed parse failed — fall back to a lightweight decode of the
	// verbatim `rules` array (mirrors Compile's legacy-graph path).
	var legacy struct {
		Rules []struct {
			Verb Verb `json:"verb"`
		} `json:"rules"`
	}
	if jerr := json.Unmarshal(pg.Graph, &legacy); jerr != nil {
		// Log jerr (the JSON-decode failure that actually
		// triggered this branch), not perr: perr is the typed
		// ParseGraph error, but here even the lightweight
		// verbatim decode failed, so jerr is the diagnostic
		// that explains why the graph is wholly unparseable.
		s.logger.Warn("policy: stored graph is unparseable; reporting empty coverage",
			slog.String("tenant_id", tenantID.String()),
			slog.String("graph_id", pg.ID.String()),
			slog.Any("error", jerr),
		)
		return nil, false
	}
	s.logger.Warn("policy: typed-graph parse failed; counting verbatim rules for coverage (legacy graph — re-publish to opt back into the typed path)",
		slog.String("tenant_id", tenantID.String()),
		slog.String("graph_id", pg.ID.String()),
		slog.Int("graph_version", pg.Version),
		slog.Any("error", perr),
	)
	verbs = make([]Verb, 0, len(legacy.Rules))
	for _, r := range legacy.Rules {
		verbs = append(verbs, r.Verb)
	}
	return verbs, true
}

// PutGraph stores a new policy graph version for the tenant. The
// version number is auto-incremented by the repository if zero.
//
// Validation runs in two layers:
//
//  1. `json.Valid` rejects syntactically broken documents.
//  2. `ParseGraph` runs the PR7 typed-schema check (valid verbs /
//     domains / targets, subject + predicate name uniqueness, rule
//     id uniqueness, subject_refs / predicate_refs resolvable
//     against the declared subjects / predicates).
//
// Failing the typed check returns a wrapped
// `repository.ErrInvalidArgument` so the handler renders 400. This
// is the "operators get schema validation at PUT time rather than
// at compile time" contract advertised in graph.go. Unknown
// top-level fields are silently ignored (Go's default
// `json.Unmarshal` behaviour) so callers can extend the document
// with PR8+ metadata without touching the validator.
func (s *Service) PutGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	return s.putGraph(ctx, tenantID, actorID, raw, false)
}

// PutDraftGraph persists a candidate graph as a draft —
// reachable via GetGraph but skipped by GetCurrentGraph. The
// rollout machinery stages a proposed graph through this path
// so the live policy stays stable until the rollout state
// machine explicitly promotes the draft to live (via
// PromoteGraph).
func (s *Service) PutDraftGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	return s.putGraph(ctx, tenantID, actorID, raw, true)
}

// PromoteGraph flips is_draft=false on a graph and appends an
// audit entry. Idempotent — promoting a live graph is a no-op.
func (s *Service) PromoteGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, id uuid.UUID) (repository.PolicyGraph, error) {
	promoted, err := s.repo.PromoteGraph(ctx, tenantID, id)
	if err != nil {
		return repository.PolicyGraph{}, err
	}
	if s.audit != nil {
		_, _ = s.audit.Append(ctx, tenantID, repository.AuditEntry{
			TenantID: tenantID, ActorID: actorID,
			Action: "policy.graph_promoted", ResourceType: "policy_graph",
			ResourceID: &promoted.ID,
		})
	}
	return promoted, nil
}

func (s *Service) putGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage, draft bool) (repository.PolicyGraph, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if !json.Valid(raw) {
		return repository.PolicyGraph{}, fmt.Errorf("invalid graph json: %w", repository.ErrInvalidArgument)
	}
	if _, err := ParseGraph(raw); err != nil {
		return repository.PolicyGraph{}, err
	}
	g := repository.PolicyGraph{
		Graph:   raw,
		IsDraft: draft,
	}
	saved, err := s.repo.CreateGraph(ctx, tenantID, g)
	if err != nil {
		return repository.PolicyGraph{}, err
	}
	if s.audit != nil {
		action := "policy.graph_updated"
		if draft {
			action = "policy.graph_drafted"
		}
		_, _ = s.audit.Append(ctx, tenantID, repository.AuditEntry{
			TenantID: tenantID, ActorID: actorID,
			Action: action, ResourceType: "policy_graph",
			ResourceID: &saved.ID,
		})
	}
	return saved, nil
}

// CompileResult is the per-target output of Compile.
type CompileResult struct {
	GraphID  uuid.UUID
	Bundles  []repository.PolicyBundle
	Targets  []repository.PolicyBundleTarget
	Compiled time.Time
}

// allTargets is the canonical, stable ordering of compile targets.
var allTargets = []repository.PolicyBundleTarget{
	repository.PolicyBundleTargetEdge,
	repository.PolicyBundleTargetEndpoint,
	repository.PolicyBundleTargetCloud,
	repository.PolicyBundleTargetMobile,
}

// Compile produces signed bundles for every enforcement target from
// the latest graph. The bundle wire format is documented in
// docs/policy-bundle.md (PR7) and consists of a MessagePack
// envelope wrapping:
//
//   - schema_version (uint8)
//   - target_type    (string)
//   - graph_id       (UUID bytes)
//   - graph_version  (int)
//   - compiler       (string)
//   - rules          (raw JSON)
//   - default_action (string, defaults to "deny")
//   - compiled_at    (RFC3339Nano string)
//
// PR7 will extend the rules section into per-target normalised
// rule sets; PR6 forwards the input verbatim so consumers already
// see a real bundle.
func (s *Service) Compile(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID) (CompileResult, error) {
	graph, err := s.repo.GetCurrentGraph(ctx, tenantID)
	if err != nil {
		return CompileResult{}, err
	}
	if s.signer == nil {
		return CompileResult{}, errors.New("policy: signer not configured")
	}

	// Pre-flight: ensure the tenant has an active signing key.
	// KeyService provisions on first use for a brand-new tenant,
	// but refuses to auto-create when the active key was just
	// revoked (signalling an incident response in progress) — see
	// KeyService.EnsureKey. Signers without persistent state (e.g.
	// EphemeralSigner) skip this step.
	if ensurer, ok := s.signer.(KeyEnsurer); ok {
		if err := ensurer.EnsureKey(ctx, tenantID); err != nil {
			return CompileResult{}, fmt.Errorf("ensure signing key: %w", err)
		}
	}

	compiledAt := time.Now().UTC()
	bundles := make([]repository.PolicyBundle, 0, len(allTargets))
	// Resolve the active signing key once via the optional
	// PreparedSigner interface. KeyService implements it; lighter
	// signers (e.g. EphemeralSigner used in handler tests) do not,
	// in which case we fall back to one Sign per target (each
	// performing its own DB lookup). The prepared path collapses
	// 4× DB round-trips + 4× wrapper.Unwrap + 4× NewKeyFromSeed
	// into one of each — Devin Review #3312683824 flagged the
	// unprepared path as a non-correctness performance issue for
	// high-throughput compiles.
	var prepared PreparedSigning
	if ps, ok := s.signer.(PreparedSigner); ok {
		prepared, err = ps.PrepareSigner(ctx, tenantID)
		if err != nil {
			return CompileResult{}, fmt.Errorf("prepare signer: %w", err)
		}
	}
	// Parse the policy graph once for the whole Compile. Each
	// target re-uses the typed result via CompileTarget; previously
	// perTargetRules called ParseGraph inside the loop, doing 4×
	// the JSON unmarshal + 4× the schema validation per compile.
	// Devin Review #3312781265 flagged this. The typed result is
	// nil-tolerant downstream: if the graph is opaque (legacy
	// PR6-era bytes that don't satisfy the typed schema), we fall
	// back to the verbatim-rules path for every target.
	var typed *Graph
	if parsed, parseErr := ParseGraph(graph.Graph); parseErr == nil {
		typed = &parsed
	} else {
		// PutGraph now validates new graphs against the typed
		// schema, so any graph that fails ParseGraph here was
		// written before that validation existed (or by a future
		// schema extension this binary doesn't recognise). The
		// fallback below produces a real bundle from the verbatim
		// rules, but skips per-target rule slicing. Devin Review
		// #3312847384 flagged the silent divergence — log a
		// warning so operators see when a tenant is on the legacy
		// path and can re-publish their graph to opt back in.
		s.logger.Warn("policy: typed-graph parse failed at compile time; falling back to verbatim-rules path (per-target rule slicing disabled for this tenant)",
			slog.String("tenant_id", tenantID.String()),
			slog.String("graph_id", graph.ID.String()),
			slog.Int("graph_version", graph.Version),
			slog.Any("error", parseErr),
		)
	}
	// Fold the tenant's inline-CASB rules into the typed graph so
	// they ride the same per-target slicing, signing, and
	// versioning as every other SWG rule. They route to the edge +
	// cloud targets via domainTargets(DomainInlineCASB). This runs
	// once per Compile (not per target): CompileTarget re-reads the
	// merged typed.Rules for each bundle. A nil compiler is a
	// no-op. When the graph is on the legacy verbatim path
	// (typed == nil) the rules cannot be merged into the parsed
	// model — log a warning rather than silently dropping them so
	// an operator can re-publish their graph to opt into the typed
	// path and get inline-CASB enforcement.
	if s.inlineCASB != nil {
		casbRules, casbErr := s.inlineCASB.CompileRules(ctx, tenantID)
		if casbErr != nil {
			return CompileResult{}, fmt.Errorf("compile inline casb rules: %w", casbErr)
		}
		if len(casbRules) > 0 {
			if typed != nil {
				typed.Rules = append(typed.Rules, casbRules...)
			} else {
				s.logger.Warn("policy: inline-CASB rules skipped for tenant on legacy verbatim-rules path (re-publish the policy graph to enable inline-CASB enforcement)",
					slog.String("tenant_id", tenantID.String()),
					slog.String("graph_id", graph.ID.String()),
					slog.Int("inline_casb_rules", len(casbRules)),
				)
			}
		}
	}
	// Fold the threat-intel IOC deny rules into the typed graph
	// alongside inline-CASB, so IP/domain/URL indicators ride the
	// same per-target slicing, signing and versioning as every
	// other rule. They route by Domain (NGFW/DNS/SWG) through
	// domainTargets. As with inline-CASB, a legacy verbatim-rules
	// graph (typed == nil) cannot absorb them — warn rather than
	// drop silently so an operator can re-publish to opt in.
	//
	// IOC rules are appended LAST (after the operator graph and
	// inline-CASB), so under the evaluator's first-match-wins
	// semantics they are lowest-priority: an explicit operator allow
	// shadows an IOC deny for the same indicator. This is intentional
	// — the operator stays in control of automated feed blocks (e.g.
	// a known false-positive host) without muting the feed. See
	// docs/THREAT_INTEL.md "Evaluation precedence".
	//
	// The IOC rules and the malicious file-hash set (compiled just
	// below for the SWG malware inspector) are derived from a single
	// store snapshot when the compiler supports it, so the two
	// enforcement planes can't diverge across a concurrent feed
	// refresh mid-compile.
	iocRules, malwareHashes, iocErr := s.compileIOCEnforcement(ctx, tenantID)
	if iocErr != nil {
		return CompileResult{}, iocErr
	}
	if len(iocRules) > 0 {
		if typed != nil {
			typed.Rules = append(typed.Rules, iocRules...)
		} else {
			s.logger.Warn("policy: threat-intel IOC rules skipped for tenant on legacy verbatim-rules path (re-publish the policy graph to enable IOC enforcement)",
				slog.String("tenant_id", tenantID.String()),
				slog.String("graph_id", graph.ID.String()),
				slog.Int("ioc_rules", len(iocRules)),
			)
		}
	}
	// malwareHashes is the same for every target; encodeBundlePayloadFor
	// includes it only in the targets that run the SWG malware
	// inspector (edge + cloud) via malwareForTarget.
	// Snapshot the appdb catalog + tenant overrides once per
	// Compile so the per-target steering build below doesn't
	// re-issue the same pair of ListAll reads for every bundle
	// target. A typical Compile produces four targets (edge,
	// endpoint, cloud, mobile) — the previous shape did 4 × 2 =
	// 8 round-trips per Compile against unchanged inputs.
	// A nil compiler (in-process tests, dry runs) leaves the
	// snapshot nil and the Steering section is omitted, matching
	// the pre-snapshot fallback behaviour.
	var steeringSnap SteeringSnapshot
	if s.steering != nil {
		snapAny, sErr := s.steering.SnapshotSteering(ctx, tenantID)
		if sErr != nil {
			return CompileResult{}, fmt.Errorf("snapshot steering: %w", sErr)
		}
		snap, ok := snapAny.(SteeringSnapshot)
		if !ok {
			return CompileResult{}, fmt.Errorf("snapshot steering: returned type %T does not implement SteeringSnapshot", snapAny)
		}
		steeringSnap = snap
	}
	for _, target := range allTargets {
		// Resolve the per-target steering rules from the
		// snapshot. Determinism comes from the appdb compiler —
		// it sorts every set into canonical order and runs at the
		// same `compiledAt` for every target, so repeated
		// compilations against an unchanged catalog produce
		// identical bytes.
		var steeringJSON json.RawMessage
		if steeringSnap != nil {
			raw, sErr := steeringSnap.CompileForTarget(target)
			if sErr != nil {
				return CompileResult{}, fmt.Errorf("compile steering rules %s: %w", target, sErr)
			}
			encoded, encErr := json.Marshal(raw)
			if encErr != nil {
				return CompileResult{}, fmt.Errorf("encode steering rules %s: %w", target, encErr)
			}
			steeringJSON = encoded
		}
		payload, err := encodeBundlePayloadFor(target, graph, typed, steeringJSON, malwareForTarget(target, malwareHashes), compiledAt)
		if err != nil {
			return CompileResult{}, fmt.Errorf("encode %s bundle: %w", target, err)
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
				return CompileResult{}, fmt.Errorf("sign %s bundle: %w", target, err)
			}
		}
		saved, err := s.repo.CreateBundle(ctx, tenantID, repository.PolicyBundle{
			PolicyGraphID: graph.ID,
			TargetType:    target,
			Bundle:        payload,
			Signature:     sig,
			KeyID:         keyID,
		})
		if err != nil {
			return CompileResult{}, fmt.Errorf("save %s bundle: %w", target, err)
		}
		bundles = append(bundles, saved)
	}
	if s.audit != nil {
		details, _ := json.Marshal(map[string]any{
			"graph_id":      graph.ID,
			"graph_version": graph.Version,
			"targets":       allTargets,
		})
		_, _ = s.audit.Append(ctx, tenantID, repository.AuditEntry{
			TenantID: tenantID, ActorID: actorID,
			Action: "policy.compiled", ResourceType: "policy_graph",
			ResourceID: &graph.ID, Details: details,
		})
	}
	return CompileResult{
		GraphID: graph.ID, Bundles: bundles,
		Targets: allTargets, Compiled: compiledAt,
	}, nil
}

// compileIOCEnforcement returns the threat-intel deny rules and the
// malicious file-hash set for the tenant, shared by Compile and
// CompileDryRun so both produce the same enforcement artefacts.
//
// When the installed IOC compiler can snapshot the store
// (IOCSnapshotCompiler), both planes are derived from ONE
// point-in-time snapshot so a concurrent feed refresh can't make the
// rule slice and the malware set disagree within a single compile.
// Otherwise it falls back to the two independent compiler calls used
// by fakes that wire the IOCCompiler and MalwareHashCompiler
// interfaces separately.
func (s *Service) compileIOCEnforcement(ctx context.Context, tenantID uuid.UUID) ([]Rule, []MalwareHashEntry, error) {
	if snapper, ok := s.sharedIOCSnapshot(); ok {
		snap, err := snapper.SnapshotIOC(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("snapshot threat-intel iocs: %w", err)
		}
		if snap == nil {
			return nil, nil, nil
		}
		rules, err := snap.CompileIOCRules()
		if err != nil {
			return nil, nil, fmt.Errorf("compile threat-intel ioc rules: %w", err)
		}
		mh, err := snap.CompileMalwareHashes()
		if err != nil {
			return nil, nil, fmt.Errorf("compile malware hashes: %w", err)
		}
		return rules, mh, nil
	}

	var rules []Rule
	if s.ioc != nil {
		r, err := s.ioc.CompileIOCRules(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("compile threat-intel ioc rules: %w", err)
		}
		rules = r
	}
	var mh []MalwareHashEntry
	if s.malwareHash != nil {
		m, err := s.malwareHash.CompileMalwareHashes(ctx, tenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("compile malware hashes: %w", err)
		}
		mh = m
	}
	return rules, mh, nil
}

// sharedIOCSnapshot reports whether the installed IOC compiler can
// derive both the rule slice and the malware set from one snapshot.
// It is only safe to take the shared path when the SAME instance
// backs both planes:
//   - A nil malware compiler must leave the malware section out
//     (the WithMalwareHashCompiler contract). The shared path
//     unconditionally compiles the malware set from the snapshot, so
//     taking it with s.malwareHash == nil would wrongly emit a
//     malware section. We fall back instead, where a nil
//     s.malwareHash yields no malware (rules still compile from one
//     snapshot — atomicity is moot with only one plane).
//   - A *different* malware compiler must not be silently bypassed,
//     so a non-nil instance that isn't s.ioc also falls back.
func (s *Service) sharedIOCSnapshot() (IOCSnapshotCompiler, bool) {
	snapper, ok := s.ioc.(IOCSnapshotCompiler)
	if !ok {
		return nil, false
	}
	if s.malwareHash == nil || any(s.malwareHash) != any(s.ioc) {
		return nil, false
	}
	return snapper, true
}

// GetLatestBundle returns the most recent bundle for a given target.
func (s *Service) GetLatestBundle(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundle, error) {
	return s.repo.GetLatestBundle(ctx, tenantID, target)
}

// GetLatestBundleMetadata returns the row-level metadata for the
// most recent bundle of `target` WITHOUT loading the bundle bytes.
// The agent-pull HEAD / 304 paths use this so a polling agent's
// conditional request never round-trips the bundle BYTEA out of
// Postgres. Returns repository.ErrNotFound when no bundle has yet
// been compiled for the (tenant, target) pair.
func (s *Service) GetLatestBundleMetadata(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundleMetadata, error) {
	return s.repo.GetLatestBundleMetadata(ctx, tenantID, target)
}

// bundlePayload is the canonical wire shape. PR7 introduced
// per-target rule transformation: the Rules field is the typed
// per-target rule slice (encoded as JSON for deterministic
// serialisation), not the full graph document. PR6 carried the
// full graph for every target, which leaked rules outside their
// enforcement domain to receivers that had no use for them.
type bundlePayload struct {
	SchemaVersion uint8           `msgpack:"v"`
	Target        string          `msgpack:"t"`
	GraphID       string          `msgpack:"g"`
	GraphVersion  int             `msgpack:"gv"`
	Compiler      string          `msgpack:"c"`
	DefaultAction string          `msgpack:"d"`
	Rules         json.RawMessage `msgpack:"r"`
	// Steering is the per-target traffic-classification rule set
	// emitted by internal/service/appdb. JSON-encoded so the
	// bundle remains deterministic byte-for-byte (the appdb
	// compiler sorts every set into canonical order). Omitted when
	// no steering compiler is wired.
	Steering json.RawMessage `msgpack:"st,omitempty"`
	// Malware is the threat-intel malicious file-hash set the SWG
	// installs into its StaticMalwareList. JSON-encoded for the
	// same byte-determinism reason as Rules/Steering. Omitted when
	// no malware-hash compiler is wired or the target does not run
	// the SWG malware inspector (only edge + cloud do).
	Malware    json.RawMessage `msgpack:"mw,omitempty"`
	CompiledAt string          `msgpack:"ts"`
}

// MalwareHashEntry is one hash -> verdict mapping in a bundle's
// malware section. Hash is lowercase hex (the canonical IOC form);
// Verdict is the SWG verdict string ("malicious" / "suspicious" /
// "clean") the Rust StaticMalwareList parses. The JSON keys are
// terse ("h"/"v") to keep the bundle compact since the malware set
// can be large.
type MalwareHashEntry struct {
	Hash    string `json:"h"`
	Verdict string `json:"v"`
}

// malwareForTarget returns the malware-hash set for a target,
// limited to the targets that run the SWG malware inspector (edge
// + cloud, matching domainTargets(DomainSWG)). Other targets get
// nil so the section is omitted from their bundle.
func malwareForTarget(target repository.PolicyBundleTarget, all []MalwareHashEntry) []MalwareHashEntry {
	if len(all) == 0 {
		return nil
	}
	switch target {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetCloud:
		return all
	default:
		return nil
	}
}

// encodeMalwareHashes canonicalises the malware-hash set for the
// bundle: entries are sorted by hash so two compilations of the
// same set produce byte-identical output, matching the determinism
// guarantee the rest of the bundle upholds. Returns nil for an
// empty set so the section is omitted.
func encodeMalwareHashes(entries []MalwareHashEntry) (json.RawMessage, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	sorted := make([]MalwareHashEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Hash != sorted[j].Hash {
			return sorted[i].Hash < sorted[j].Hash
		}
		return sorted[i].Verdict < sorted[j].Verdict
	})
	return json.Marshal(sorted)
}

// encodeBundlePayload renders a deterministic, MessagePack-encoded
// bundle. Determinism is essential — two compilations of the same
// input must produce byte-identical output so the signature can be
// verified out-of-band and bundles can be cached/deduped at the
// edge.
//
// The bundle's Rules field carries only the rules that apply to
// the given target, computed via Graph.CompileTarget (per
// ARCHITECTURE.md §3.2 + §5). When the typed graph cannot be
// parsed (older opaque-JSON graphs from PR6, or future schema
// extensions we don't recognise), we fall back to the previous
// behaviour and forward the verbatim `rules` sub-document so
// receivers still see a real bundle.
func encodeBundlePayload(target repository.PolicyBundleTarget, g repository.PolicyGraph, compiledAt time.Time) ([]byte, error) {
	// Single-shot helper: parse the graph here so external callers
	// (today: the determinism test in compile_test.go) get the same
	// bytes Compile would produce. Compile itself uses
	// encodeBundlePayloadFor with a graph it has already parsed
	// once for the whole compile run.
	var typed *Graph
	if parsed, err := ParseGraph(g.Graph); err == nil {
		typed = &parsed
	}
	return encodeBundlePayloadFor(target, g, typed, nil, nil, compiledAt)
}

// encodeBundlePayloadFor renders a deterministic, MessagePack-encoded
// bundle. typed may be nil — when it is, the function falls back to
// the verbatim-rules path so opaque legacy graphs still produce a
// real bundle. Compile parses the graph once and threads the typed
// result through every per-target call, replacing the 4× ParseGraph
// per Compile that Devin Review #3312781265 flagged.
//
// steeringJSON is the canonical-JSON encoding of the per-target
// traffic-classification rule set (see internal/service/appdb.
// SteeringRuleSet). nil means "no steering compiler was wired"; the
// bundle omits the section in that case.
//
// malware is the malicious file-hash set for this target (already
// filtered to edge/cloud by malwareForTarget). nil/empty omits the
// malware section.
func encodeBundlePayloadFor(target repository.PolicyBundleTarget, g repository.PolicyGraph, typed *Graph, steeringJSON json.RawMessage, malware []MalwareHashEntry, compiledAt time.Time) ([]byte, error) {
	rules, defaultAction := perTargetRulesFromParsed(target, g.Graph, typed)
	malwareJSON, err := encodeMalwareHashes(malware)
	if err != nil {
		return nil, fmt.Errorf("encode malware hashes: %w", err)
	}
	p := bundlePayload{
		SchemaVersion: 1,
		Target:        string(target),
		GraphID:       g.ID.String(),
		GraphVersion:  g.Version,
		Compiler:      CompilerVersion,
		DefaultAction: defaultAction,
		Rules:         rules,
		Steering:      steeringJSON,
		Malware:       malwareJSON,
		CompiledAt:    compiledAt.Format(time.RFC3339Nano),
	}
	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)
	// Stable key order is achieved via the explicit msgpack tag
	// ordering on the struct (msgpack/v5 walks struct fields in
	// declaration order).
	return msgpack.Marshal(&p)
}

// perTargetRulesFromParsed is the post-refactor per-target helper:
// when typed != nil it uses the already-parsed graph (no JSON work);
// when typed == nil it falls back to the verbatim-rules path. The
// fallback is the same shape as the pre-refactor perTargetRules
// behaviour for an unparseable graph.
func perTargetRulesFromParsed(target repository.PolicyBundleTarget, raw json.RawMessage, typed *Graph) (json.RawMessage, string) {
	if typed == nil {
		return normaliseRules(raw), extractDefaultAction(raw)
	}
	selected := typed.CompileTarget(target)
	rules, err := EncodeRules(selected)
	if err != nil {
		return normaliseRules(raw), string(typed.DefaultAction)
	}
	return rules, string(typed.DefaultAction)
}

// normaliseRules canonicalises the JSON sub-document under "rules"
// so determinism holds across compilations. Empty / missing input
// yields a JSON null so the bundle still validates.
func normaliseRules(graph json.RawMessage) json.RawMessage {
	if len(graph) == 0 {
		return json.RawMessage(`null`)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(graph, &root); err != nil {
		// Treat unparseable graph as empty rule set — Compile's
		// PutGraph rejects invalid JSON, so this is only reachable
		// if a future writer stored garbage directly.
		return json.RawMessage(`null`)
	}
	raw, ok := root["rules"]
	if !ok {
		return json.RawMessage(`null`)
	}
	// Re-encode to canonical form (sorted keys, no whitespace) so
	// equivalent JSON inputs produce identical bytes.
	canonical, err := canonicaliseJSON(raw)
	if err != nil {
		return raw
	}
	return canonical
}

// extractDefaultAction reads the `default_action` field from the
// graph JSON, defaulting to "deny" (safe baseline).
func extractDefaultAction(graph json.RawMessage) string {
	if len(graph) == 0 {
		return "deny"
	}
	var probe struct {
		DefaultAction string `json:"default_action"`
	}
	if err := json.Unmarshal(graph, &probe); err != nil {
		return "deny"
	}
	if probe.DefaultAction == "" {
		return "deny"
	}
	return probe.DefaultAction
}

// canonicaliseJSON re-encodes any JSON value with sorted object
// keys so equivalent inputs produce byte-identical output. This is
// the same property the PR7 compiler will need for its determinism
// tests.
func canonicaliseJSON(raw json.RawMessage) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return marshalSorted(v)
}

func marshalSorted(v any) (json.RawMessage, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, _ := json.Marshal(k)
			out = append(out, kb...)
			out = append(out, ':')
			child, err := marshalSorted(t[k])
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, '}')
		return out, nil
	case []any:
		out := []byte{'['}
		for i, item := range t {
			if i > 0 {
				out = append(out, ',')
			}
			child, err := marshalSorted(item)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, ']')
		return out, nil
	default:
		return json.Marshal(t)
	}
}

// --- Signer implementations ------------------------------------------------

// EphemeralSigner generates a fresh Ed25519 key at construction and
// uses it for all signatures. It's suitable for tests and for the
// PR6 wiring; production deployments will switch to a config-loaded
// or KMS-backed signer in PR8.
type EphemeralSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewEphemeralSigner returns a signer with a freshly generated key
// pair. The public key is exposed via PublicKey() so callers can
// distribute it to verifiers.
func NewEphemeralSigner() (*EphemeralSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EphemeralSigner{pub: pub, priv: priv}, nil
}

// Sign produces an Ed25519 signature over data. The returned
// KeyID is empty because EphemeralSigner is not tied to any
// persisted key — receivers using this signer must fetch the
// public key out-of-band via PublicKey().
func (s *EphemeralSigner) Sign(_ context.Context, _ uuid.UUID, data []byte) ([]byte, string, error) {
	return ed25519.Sign(s.priv, data), "", nil
}

// PublicKey returns the verification key.
func (s *EphemeralSigner) PublicKey() ed25519.PublicKey { return s.pub }

// KeySigner uses a pre-loaded Ed25519 private key.  This is the
// production path for deployments that bootstrap a signing key
// out-of-band (config file at `POLICY_SIGNING_KEY_PATH`) instead of
// going through DB-backed rotation.  Single key, single tenant set
// — operators rotating the key replace the file and restart the
// process; the new key takes over on next boot.  There is no
// in-process rotation in this mode by design (rotation lives in
// KeyService).
//
// KeyID is derived from the public key at construction time so the
// bundle envelope's `kid` field is stable across restarts (callers
// only need the private key file — the public half is recomputable
// from the seed). The derivation is the first 16 hex characters of
// SHA-256(public), giving 64 bits of identification — comfortably
// distinct across a small operator-managed key inventory while
// staying short enough for log readability.
type KeySigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

// NewKeySigner returns a signer backed by the given private key.
// `priv` must be a full ed25519.PrivateKey (64 bytes); callers that
// have only a 32-byte seed should construct one via
// `ed25519.NewKeyFromSeed(seed)` first.
func NewKeySigner(priv ed25519.PrivateKey) *KeySigner {
	if len(priv) != ed25519.PrivateKeySize {
		// Documented invariant; callers that hand us a malformed
		// key should fail loudly at construction rather than
		// shipping malformed signatures.
		panic(fmt.Sprintf("policy: NewKeySigner expects a %d-byte ed25519 private key, got %d", ed25519.PrivateKeySize, len(priv)))
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &KeySigner{priv: priv, keyID: deriveKeyID(pub)}
}

// PublicKey returns the verification half of the signer's key. The
// readiness handler publishes this so receivers can verify bundles
// without an out-of-band trust step.
func (s *KeySigner) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// KeyID returns the stable identifier embedded in the bundle
// envelope's `kid` field.
func (s *KeySigner) KeyID() string { return s.keyID }

// Sign produces an Ed25519 signature.
func (s *KeySigner) Sign(_ context.Context, _ uuid.UUID, data []byte) ([]byte, string, error) {
	return ed25519.Sign(s.priv, data), s.keyID, nil
}

// PrepareSigner returns a PreparedSigning bound to this signer's
// private key. KeySigner satisfies the optional PreparedSigner
// interface so Compile can sign all per-target payloads against a
// single pure-CPU signer (no DB hop per target).
func (s *KeySigner) PrepareSigner(_ context.Context, _ uuid.UUID) (PreparedSigning, error) {
	return &preparedKeySigner{priv: s.priv, keyID: s.keyID}, nil
}

type preparedKeySigner struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (p *preparedKeySigner) Sign(data []byte) ([]byte, string) {
	return ed25519.Sign(p.priv, data), p.keyID
}

// deriveKeyID maps a public key to a stable short identifier. The
// shape — first 16 hex chars of SHA-256(public) — matches the
// PR7 KeyService.newKeyID convention so log filters and receiver-side
// verification code are uniform across signer implementations.
//
// The two derivations use intentionally different sources:
//
//   - KeyService.newKeyID(): first 8 bytes of a fresh UUID v4
//     (≈60 bits of entropy, fresh per rotation)
//   - KeySigner.deriveKeyID(): first 8 bytes of SHA-256(public)
//     (64 bits of effective entropy, deterministic in the public
//     key so it's stable across restarts of the same file-backed
//     deployment)
//
// The shape (16 hex chars) is the same so log filters and the
// receiver's verification code don't need to know which signer
// produced a given kid. Cross-mode collision probability between
// a file-backed kid and a DB-backed kid is bounded by the lower
// entropy source (≈2⁻⁶⁰ per pair); across a tenant with ~1000
// historical DB rotations plus 1 file-backed key, by birthday-style
// reasoning the probability of any collision is ~10⁻¹⁵ —
// astronomically negligible.
func deriveKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
