package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// EndpointSchemaVersion is the schema version of the endpoint DLP
// policy blob this service emits. It must stay in lock-step with
// sng-dlp's `policy::MAX_SUPPORTED_SCHEMA_VERSION`: the agent
// fail-closes on a newer version than it understands.
const EndpointSchemaVersion = 1

// endpointDomain is the policy-graph enforcement domain endpoint DLP
// rules compile under. Mirrors sng_policy_eval::EnforcementDomain::Dlp.
const endpointDomain = "dlp"

// EndpointDLPChannel is an on-device egress channel the agent
// inspects. The string values are wire-identical to sng-dlp's
// `DlpChannel` (snake_case).
type EndpointDLPChannel string

// The supported endpoint egress channels.
const (
	EndpointChannelClipboard     EndpointDLPChannel = "clipboard"
	EndpointChannelFileWrite     EndpointDLPChannel = "file_write"
	EndpointChannelPrint         EndpointDLPChannel = "print"
	EndpointChannelUSBTransfer   EndpointDLPChannel = "usb_transfer"
	EndpointChannelBrowserUpload EndpointDLPChannel = "browser_upload"
)

// AllEndpointChannels lists every channel in declaration order.
func AllEndpointChannels() []EndpointDLPChannel {
	return []EndpointDLPChannel{
		EndpointChannelClipboard,
		EndpointChannelFileWrite,
		EndpointChannelPrint,
		EndpointChannelUSBTransfer,
		EndpointChannelBrowserUpload,
	}
}

// EndpointDLPSeverity classifies a rule's sensitivity. Wire-identical
// to sng-dlp's `Severity`.
type EndpointDLPSeverity string

// Endpoint severity levels, least to most sensitive.
const (
	EndpointSeverityLow      EndpointDLPSeverity = "low"
	EndpointSeverityMedium   EndpointDLPSeverity = "medium"
	EndpointSeverityHigh     EndpointDLPSeverity = "high"
	EndpointSeverityCritical EndpointDLPSeverity = "critical"
)

// EndpointDLPAction is the action the endpoint takes on a match.
// Wire-identical to sng-dlp's `RuleAction`. The endpoint vocabulary
// is narrower than the web/SaaS DLPAction set: the endpoint cannot
// encrypt or redact content in-flight, so those web actions are
// mapped onto the strongest applicable endpoint action by
// [endpointAction].
type EndpointDLPAction string

// Endpoint actions, least to most strict.
const (
	EndpointActionLog   EndpointDLPAction = "log"
	EndpointActionWarn  EndpointDLPAction = "warn"
	EndpointActionBlock EndpointDLPAction = "block"
)

// EndpointDLPRule is a single endpoint detection rule, in the exact
// JSON shape sng-dlp's `DlpRule` deserializes.
type EndpointDLPRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	PatternType repository.DLPRuleType `json:"pattern_type"`
	PatternData string                 `json:"pattern_data"`
	Severity    EndpointDLPSeverity    `json:"severity"`
	Action      EndpointDLPAction      `json:"action"`
	Channels    []EndpointDLPChannel   `json:"channels"`
}

// EndpointChannelConfig is the per-channel configuration carried in
// the endpoint policy. Wire-identical to sng-dlp's `ChannelConfig`.
type EndpointChannelConfig struct {
	Enabled        bool               `json:"enabled"`
	ActionOverride *EndpointDLPAction `json:"action_override,omitempty"`
}

// EndpointDLPModel is the on-device ML NER model descriptor carried
// in the endpoint bundle. It is emitted only when the tenant has an
// assigned, validated model AND the compiled rule set contains at
// least one `ml_ner` rule (shipping a model no rule references would
// be dead weight). The agent fetches the ONNX bytes by ObjectKey
// from the bundle distribution channel, verifies them against SHA256
// and Signature (sng-dlp's `ModelVerifier`, the same Ed25519 trust
// chain as the policy bundle), and hot-swaps the classifier; a
// missing/failed model leaves the agent on regex-only NER.
type EndpointDLPModel struct {
	Version       int      `json:"version"`
	EntityClasses []string `json:"entity_classes"`
	ObjectKey     string   `json:"object_key"`
	SizeBytes     int64    `json:"size_bytes"`
	SHA256        string   `json:"sha256"`
	Signature     string   `json:"signature"`
}

// EndpointAiAppPolicy is the operator policy for the endpoint AI-app
// exfiltration detector. Wire-identical to sng-dlp's `AiAppPolicy`
// (the field names + JSON tags must match exactly so
// `DlpPolicy::from_bundle_json` decodes it). The agent arms the
// detector with this policy on bundle apply.
//
// The default ([DefaultEndpointAiAppPolicy]) is deliberately
// coach-first and non-blocking: it monitors and coaches but never
// blocks until an operator opts in (BlockOptIn). This is the posture
// the HITL review-queue producer depends on — arming it is what turns
// the producer live at the edge.
type EndpointAiAppPolicy struct {
	Enabled             bool                `json:"enabled"`
	BlockOptIn          bool                `json:"block_opt_in"`
	BlockConfidence     float64             `json:"block_confidence"`
	MinReportConfidence float64             `json:"min_report_confidence"`
	CoachSeverityFloor  EndpointDLPSeverity `json:"coach_severity_floor"`
}

// DefaultEndpointAiAppPolicy returns the coach-first, non-blocking
// default, byte-identical to sng-dlp's `AiAppPolicy::default`: enabled,
// never blocking (BlockOptIn false), only surfacing high-severity
// findings at ≥0.5 confidence as nudges. This caps the false-positive
// blast radius for the 5000-tenant fleet while still making the
// detector live.
func DefaultEndpointAiAppPolicy() EndpointAiAppPolicy {
	return EndpointAiAppPolicy{
		Enabled:             true,
		BlockOptIn:          false,
		BlockConfidence:     0.9,
		MinReportConfidence: 0.5,
		CoachSeverityFloor:  EndpointSeverityHigh,
	}
}

// EndpointDLPPolicy is the endpoint-bundle DLP-domain payload. It is
// the document sng-dlp's `DlpPolicy::from_bundle_json` decodes. The
// optional `model` field is forward-compatible: sng-dlp's decoder
// does not set `deny_unknown_fields`, so agents that predate ML NER
// ignore it. The optional `ai_app` field is likewise forward-
// compatible: agents predating the AI-app detector ignore it.
type EndpointDLPPolicy struct {
	SchemaVersion int                                          `json:"schema_version"`
	Target        repository.PolicyBundleTarget                `json:"target"`
	Domain        string                                       `json:"domain"`
	Rules         []EndpointDLPRule                            `json:"rules"`
	Channels      map[EndpointDLPChannel]EndpointChannelConfig `json:"channels,omitempty"`
	Model         *EndpointDLPModel                            `json:"model,omitempty"`
	AiApp         *EndpointAiAppPolicy                         `json:"ai_app,omitempty"`
}

// DefaultEndpointChannelConfig returns the default channel map: every
// channel enabled with no action floor. Callers can mutate it before
// passing to [Service.CompileEndpointBundle].
func DefaultEndpointChannelConfig() map[EndpointDLPChannel]EndpointChannelConfig {
	cfg := make(map[EndpointDLPChannel]EndpointChannelConfig, len(AllEndpointChannels()))
	for _, ch := range AllEndpointChannels() {
		cfg[ch] = EndpointChannelConfig{Enabled: true}
	}
	return cfg
}

// EndpointRules compiles the tenant's enabled web/SaaS DLP policies
// into the endpoint rule set. This is the read side of endpoint DLP
// rule management: the same stored policies that drive inline
// classification are projected onto the endpoint's rule vocabulary.
func (s *Service) EndpointRules(ctx context.Context, tenantID uuid.UUID) ([]EndpointDLPRule, error) {
	policies, err := s.policies.ListEnabled(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return compileEndpointRules(policies), nil
}

// CompileEndpointBundle compiles the tenant's enabled DLP policies
// into the endpoint-bundle DLP-domain payload and marshals it to the
// JSON blob the agent loads. A nil channels map defaults to
// [DefaultEndpointChannelConfig].
func (s *Service) CompileEndpointBundle(
	ctx context.Context,
	tenantID uuid.UUID,
	channels map[EndpointDLPChannel]EndpointChannelConfig,
) ([]byte, error) {
	policies, err := s.policies.ListEnabled(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if channels == nil {
		channels = DefaultEndpointChannelConfig()
	}
	rules := compileEndpointRules(policies)
	model, err := s.endpointModel(ctx, tenantID, rules)
	if err != nil {
		return nil, err
	}
	// Arm the AI-app exfiltration detector coach-first by default.
	// The agent only applies this when it runs endpoint DLP (its own
	// `[dlp] enabled` gate), so this is opt-in at deployment and
	// non-blocking until an operator opts into blocking. This is the
	// wiring that makes the HITL review-queue producer live.
	aiApp := DefaultEndpointAiAppPolicy()
	policy := EndpointDLPPolicy{
		SchemaVersion: EndpointSchemaVersion,
		Target:        repository.PolicyBundleTargetEndpoint,
		Domain:        endpointDomain,
		Rules:         rules,
		Channels:      channels,
		Model:         model,
		AiApp:         &aiApp,
	}
	if err := ValidateEndpointPolicy(policy); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

// endpointModel returns the ML NER model descriptor to embed in the
// tenant's endpoint bundle, or nil when none should be embedded. A
// model is embedded only when (a) the model registry is wired, (b)
// the compiled rule set contains at least one ml_ner rule, and (c)
// the tenant has an assigned model that is in the validated state.
// Any other case (no assignment, a draft/retired assignment, or no
// ml_ner rule) returns nil: the agent runs regex-only NER, the
// documented fail-safe. A genuine repository error (not ErrNotFound)
// is propagated so a flaky datastore does not silently strip a
// model.
func (s *Service) endpointModel(
	ctx context.Context,
	tenantID uuid.UUID,
	rules []EndpointDLPRule,
) (*EndpointDLPModel, error) {
	if s.models == nil || !rulesContainMLNER(rules) {
		return nil, nil
	}
	m, err := s.models.GetAssignedModel(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if m.Status != repository.DLPModelStatusValidated {
		return nil, nil
	}
	return &EndpointDLPModel{
		Version:       m.Version,
		EntityClasses: m.EntityClasses,
		ObjectKey:     m.ObjectKey,
		SizeBytes:     m.SizeBytes,
		SHA256:        m.SHA256,
		Signature:     m.Signature,
	}, nil
}

// rulesContainMLNER reports whether any compiled endpoint rule uses
// the ml_ner pattern type.
func rulesContainMLNER(rules []EndpointDLPRule) bool {
	for _, r := range rules {
		if r.PatternType == repository.DLPRuleTypeMLNER {
			return true
		}
	}
	return false
}

// compileEndpointRules flattens a set of policies into endpoint
// rules. A policy with N rules normally yields N endpoint rules, each
// tagged with a stable `<policy-id>:<index>` id so the agent's audit
// trail can attribute a match back to the source policy.
//
// One web rule can expand to more than one endpoint rule: an MIP-label
// rule that carries both a label id and a sensitivity level is an OR
// match on the web side, but the endpoint rule's single `pattern_data`
// holds only one match path. To preserve the web OR-semantics without
// widening the wire schema, such a rule is split into two endpoint
// rules — `<policy-id>:<index>:label` and `<policy-id>:<index>:sens` —
// that both attribute back to the same source policy.
func compileEndpointRules(policies []repository.DLPPolicy) []EndpointDLPRule {
	// Non-nil so a tenant with no enabled policies marshals to
	// `"rules": []`, not `"rules": null`. sng-dlp's `#[serde(default)]`
	// only fills a missing key, so a present null would fail to decode
	// into Vec<DlpRule> and break the bundle for every empty tenant.
	rules := make([]EndpointDLPRule, 0)
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		for i, r := range p.Rules {
			baseID := fmt.Sprintf("%s:%d", p.ID, i)
			for _, m := range endpointMatchPaths(r) {
				// Skip a match path whose payload can't produce a working
				// sng-dlp rule. An empty pattern_data never matches
				// meaningfully (an MIP label "" or empty keyword dictionary
				// is a no-op; an empty regex matches everything), and a
				// fingerprint payload that isn't a 16-char hex SimHash —
				// the only shape sng-dlp's parse_simhash_hex accepts —
				// would make the agent reject the ENTIRE bundle on decode.
				// (Web fingerprint matching is repository-driven, so a
				// fingerprint rule's Pattern is not guaranteed to hold the
				// hex hash.) Dropping the dead/poison path keeps one
				// misconfigured rule from taking down every other rule.
				if !validEndpointPatternData(r.Type, m.patternData) {
					continue
				}
				rules = append(rules, EndpointDLPRule{
					ID:          baseID + m.idSuffix,
					Name:        p.Name,
					PatternType: r.Type,
					PatternData: m.patternData,
					Severity:    endpointSeverity(p.Action),
					Action:      endpointAction(p.Action),
					// Web/SaaS policies are not channel-scoped, so each
					// rule applies to every endpoint channel (empty list
					// = all channels in sng-dlp).
					Channels: []EndpointDLPChannel{},
				})
			}
		}
	}
	return rules
}

// endpointMatch is one compiled match path: the `pattern_data` payload
// sng-dlp inspects and the id suffix that disambiguates it when a
// single web rule yields more than one endpoint rule.
type endpointMatch struct {
	idSuffix    string
	patternData string
}

// endpointMatchPaths expands a web DLP rule into the endpoint match
// paths it should compile to.
//
// Web DLP treats an MIP-label rule's label id and sensitivity level as
// an OR match. The endpoint rule's single `pattern_data` can only hold
// one of them, so a rule with both set is split into two paths
// (`:label` and `:sens`) to keep the OR-semantics; a rule with just one
// of the two collapses to that one. Every other rule type (and any MIP
// rule with neither field) yields a single unsuffixed path carrying its
// raw payload (regex source, keyword dictionary, fingerprint hex).
func endpointMatchPaths(r repository.DLPRule) []endpointMatch {
	if r.Type == repository.DLPRuleTypeMIPLabel {
		if r.Pattern != "" && r.SensitivityLevel != "" {
			return []endpointMatch{
				{idSuffix: ":label", patternData: r.Pattern},
				{idSuffix: ":sens", patternData: r.SensitivityLevel},
			}
		}
		if r.Pattern == "" {
			return []endpointMatch{{patternData: r.SensitivityLevel}}
		}
	}
	return []endpointMatch{{patternData: r.Pattern}}
}

// validEndpointPatternData reports whether a compiled match path can
// produce a working sng-dlp rule. Every type needs a non-empty payload;
// a fingerprint payload must additionally be a 16-char hex SimHash — the
// shape sng-dlp's `parse_simhash_hex` accepts. An unparseable fingerprint
// payload is special: sng-dlp fails the whole-bundle compile on it rather
// than just that rule, so emitting one would drop every rule for the
// tenant. Validating here turns that bundle-wide poison into an isolated
// drop of the single offending rule.
func validEndpointPatternData(t repository.DLPRuleType, data string) bool {
	if data == "" {
		return false
	}
	switch t {
	case repository.DLPRuleTypeFingerprint:
		return isHex16(data)
	case repository.DLPRuleTypeMLNER:
		return validEntityClassCSV(data)
	default:
		return true
	}
}

// endpointEntityClasses is the set of NER entity-class wire names an
// ml_ner rule may target. Wire-identical to sng-dlp's `EntityClass`.
var endpointEntityClasses = map[string]struct{}{
	"person_name":           {},
	"address":               {},
	"phone_number":          {},
	"bank_account":          {},
	"medical_record":        {},
	"legal_document":        {},
	"medical_record_number": {},
	"driver_license":        {},
	"tax_id":                {},
	"date_of_birth":         {},
	"passport_number":       {},
	"national_id":           {},
}

// validEntityClassCSV reports whether data is a comma-separated list
// resolving to at least one known entity-class wire name. It mirrors
// sng-dlp's `parse_entity_classes`: entries are trimmed, empty
// entries are skipped, an unknown name is rejected, and the
// effective list must be non-empty. Keeping this in lock-step means
// the control plane rejects a poison ml_ner payload here rather than
// letting the agent fail the whole-bundle compile.
func validEntityClassCSV(data string) bool {
	found := false
	for _, raw := range strings.Split(data, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, ok := endpointEntityClasses[name]; !ok {
			return false
		}
		found = true
	}
	return found
}

// isHex16 reports whether s is exactly 16 hexadecimal digits (the
// hex encoding of an 8-byte big-endian SimHash, as produced by
// engine.RegisterFingerprint and decoded by sng-dlp's parse_simhash_hex).
func isHex16(s string) bool {
	return isHexLen(s, 16)
}

// isHexLen reports whether s is exactly n hexadecimal digits.
func isHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

// endpointAction maps a web/SaaS DLPAction onto the endpoint's
// narrower action set:
//
//   - log     → log   (record only)
//   - redact  → warn  (the endpoint cannot redact in-flight content,
//     so it warns the user instead)
//   - encrypt → block (the endpoint cannot encrypt egress, so it
//     fails closed)
//   - block   → block
func endpointAction(a repository.DLPAction) EndpointDLPAction {
	switch a {
	case repository.DLPActionBlock, repository.DLPActionEncrypt:
		return EndpointActionBlock
	case repository.DLPActionRedact:
		return EndpointActionWarn
	case repository.DLPActionLog:
		return EndpointActionLog
	default:
		return EndpointActionLog
	}
}

// endpointSeverity derives a severity from the policy action: the
// stricter the requested action, the more sensitive the data class
// is assumed to be.
func endpointSeverity(a repository.DLPAction) EndpointDLPSeverity {
	switch a {
	case repository.DLPActionBlock, repository.DLPActionEncrypt:
		return EndpointSeverityCritical
	case repository.DLPActionRedact:
		return EndpointSeverityHigh
	case repository.DLPActionLog:
		return EndpointSeverityMedium
	default:
		return EndpointSeverityMedium
	}
}

// ValidateEndpointPolicy checks the structural invariants sng-dlp's
// decoder enforces, so a malformed bundle is caught at compile time
// on the control plane rather than fail-closing on the agent.
func ValidateEndpointPolicy(p EndpointDLPPolicy) error {
	if p.Target != repository.PolicyBundleTargetEndpoint {
		return fmt.Errorf("%w: endpoint DLP policy target must be endpoint, got %q",
			repository.ErrInvalidArgument, p.Target)
	}
	if p.Domain != endpointDomain {
		return fmt.Errorf("%w: endpoint DLP policy domain must be dlp, got %q",
			repository.ErrInvalidArgument, p.Domain)
	}
	if p.SchemaVersion > EndpointSchemaVersion {
		return fmt.Errorf("%w: endpoint DLP schema version %d exceeds supported %d",
			repository.ErrInvalidArgument, p.SchemaVersion, EndpointSchemaVersion)
	}
	seen := make(map[string]struct{}, len(p.Rules))
	for _, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("%w: endpoint DLP rule with empty id", repository.ErrInvalidArgument)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("%w: duplicate endpoint DLP rule id %q",
				repository.ErrInvalidArgument, r.ID)
		}
		seen[r.ID] = struct{}{}
		if !validRuleType(r.PatternType) {
			return fmt.Errorf("%w: unknown endpoint DLP rule type %q",
				repository.ErrInvalidArgument, r.PatternType)
		}
		for _, ch := range r.Channels {
			if !validEndpointChannel(ch) {
				return fmt.Errorf("%w: unknown endpoint DLP channel %q",
					repository.ErrInvalidArgument, ch)
			}
		}
	}
	channels := make([]EndpointDLPChannel, 0, len(p.Channels))
	for ch := range p.Channels {
		channels = append(channels, ch)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i] < channels[j] })
	for _, ch := range channels {
		if !validEndpointChannel(ch) {
			return fmt.Errorf("%w: unknown endpoint DLP channel %q",
				repository.ErrInvalidArgument, ch)
		}
	}
	if p.AiApp != nil {
		// Mirror sng-dlp's DlpPolicy::validate so a malformed AI-app
		// policy is caught here rather than fail-closing on the agent.
		for _, c := range []struct {
			name string
			val  float64
		}{
			{"block_confidence", p.AiApp.BlockConfidence},
			{"min_report_confidence", p.AiApp.MinReportConfidence},
		} {
			if c.val < 0 || c.val > 1 {
				return fmt.Errorf("%w: endpoint DLP ai_app %s %g out of [0,1]",
					repository.ErrInvalidArgument, c.name, c.val)
			}
		}
		if !validEndpointSeverity(p.AiApp.CoachSeverityFloor) {
			return fmt.Errorf("%w: endpoint DLP ai_app coach_severity_floor %q invalid",
				repository.ErrInvalidArgument, p.AiApp.CoachSeverityFloor)
		}
	}
	return nil
}

func validEndpointSeverity(s EndpointDLPSeverity) bool {
	switch s {
	case EndpointSeverityLow, EndpointSeverityMedium, EndpointSeverityHigh, EndpointSeverityCritical:
		return true
	default:
		return false
	}
}

func validEndpointChannel(ch EndpointDLPChannel) bool {
	switch ch {
	case EndpointChannelClipboard, EndpointChannelFileWrite, EndpointChannelPrint,
		EndpointChannelUSBTransfer, EndpointChannelBrowserUpload:
		return true
	default:
		return false
	}
}
