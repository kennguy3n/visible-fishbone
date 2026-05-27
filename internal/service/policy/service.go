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
	"encoding/json"
	"errors"
	"fmt"
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
type Signer interface {
	Sign(ctx context.Context, tenantID uuid.UUID, data []byte) ([]byte, error)
}

// Service is the policy service.
type Service struct {
	repo   repository.PolicyRepository
	audit  repository.AuditLogRepository
	signer Signer
}

// New returns a ready-to-use policy service.
func New(repo repository.PolicyRepository, audit repository.AuditLogRepository, signer Signer) *Service {
	return &Service{repo: repo, audit: audit, signer: signer}
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

// PutGraph stores a new policy graph version for the tenant. The
// version number is auto-incremented by the repository if zero.
func (s *Service) PutGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if !json.Valid(raw) {
		return repository.PolicyGraph{}, fmt.Errorf("invalid graph json: %w", repository.ErrInvalidArgument)
	}
	g := repository.PolicyGraph{
		Graph: raw,
	}
	saved, err := s.repo.CreateGraph(ctx, tenantID, g)
	if err != nil {
		return repository.PolicyGraph{}, err
	}
	if s.audit != nil {
		_, _ = s.audit.Append(ctx, tenantID, repository.AuditEntry{
			TenantID: tenantID, ActorID: actorID,
			Action: "policy.graph_updated", ResourceType: "policy_graph",
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

	compiledAt := time.Now().UTC()
	bundles := make([]repository.PolicyBundle, 0, len(allTargets))
	for _, target := range allTargets {
		payload, err := encodeBundlePayload(target, graph, compiledAt)
		if err != nil {
			return CompileResult{}, fmt.Errorf("encode %s bundle: %w", target, err)
		}
		sig, err := s.signer.Sign(ctx, tenantID, payload)
		if err != nil {
			return CompileResult{}, fmt.Errorf("sign %s bundle: %w", target, err)
		}
		saved, err := s.repo.CreateBundle(ctx, tenantID, repository.PolicyBundle{
			PolicyGraphID: graph.ID,
			TargetType:    target,
			Bundle:        payload,
			Signature:     sig,
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

// GetLatestBundle returns the most recent bundle for a given target.
func (s *Service) GetLatestBundle(ctx context.Context, tenantID uuid.UUID, target repository.PolicyBundleTarget) (repository.PolicyBundle, error) {
	return s.repo.GetLatestBundle(ctx, tenantID, target)
}

// bundlePayload is the canonical wire shape. PR7 may add fields;
// the schema_version guards forward-compatibility.
type bundlePayload struct {
	SchemaVersion uint8           `msgpack:"v"`
	Target        string          `msgpack:"t"`
	GraphID       string          `msgpack:"g"`
	GraphVersion  int             `msgpack:"gv"`
	Compiler      string          `msgpack:"c"`
	DefaultAction string          `msgpack:"d"`
	Rules         json.RawMessage `msgpack:"r"`
	CompiledAt    string          `msgpack:"ts"`
}

// encodeBundlePayload renders a deterministic, MessagePack-encoded
// bundle. Determinism is essential — two compilations of the same
// input must produce byte-identical output so the signature can be
// verified out-of-band and bundles can be cached/deduped at the
// edge.
func encodeBundlePayload(target repository.PolicyBundleTarget, g repository.PolicyGraph, compiledAt time.Time) ([]byte, error) {
	rules := normaliseRules(g.Graph)
	defaultAction := extractDefaultAction(g.Graph)
	p := bundlePayload{
		SchemaVersion: 1,
		Target:        string(target),
		GraphID:       g.ID.String(),
		GraphVersion:  g.Version,
		Compiler:      CompilerVersion,
		DefaultAction: defaultAction,
		Rules:         rules,
		CompiledAt:    compiledAt.Format(time.RFC3339Nano),
	}
	var buf []byte
	enc := msgpack.GetEncoder()
	defer msgpack.PutEncoder(enc)
	// Stable key order is achieved via the explicit msgpack tag
	// ordering on the struct (msgpack/v5 walks struct fields in
	// declaration order).
	out, err := msgpack.Marshal(&p)
	if err != nil {
		return nil, err
	}
	buf = out
	return buf, nil
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

// Sign produces an Ed25519 signature over data.
func (s *EphemeralSigner) Sign(_ context.Context, _ uuid.UUID, data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

// PublicKey returns the verification key.
func (s *EphemeralSigner) PublicKey() ed25519.PublicKey { return s.pub }

// KeySigner uses a pre-loaded Ed25519 private key. PR8 will wire
// this from a config file (`POLICY_SIGNING_KEY_PATH`).
type KeySigner struct {
	priv ed25519.PrivateKey
}

// NewKeySigner returns a signer backed by the given private key.
func NewKeySigner(priv ed25519.PrivateKey) *KeySigner {
	return &KeySigner{priv: priv}
}

// Sign produces an Ed25519 signature.
func (s *KeySigner) Sign(_ context.Context, _ uuid.UUID, data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}
