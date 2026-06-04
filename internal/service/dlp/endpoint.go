package dlp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

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

// EndpointDLPPolicy is the endpoint-bundle DLP-domain payload. It is
// the document sng-dlp's `DlpPolicy::from_bundle_json` decodes.
type EndpointDLPPolicy struct {
	SchemaVersion int                                          `json:"schema_version"`
	Target        repository.PolicyBundleTarget                `json:"target"`
	Domain        string                                       `json:"domain"`
	Rules         []EndpointDLPRule                            `json:"rules"`
	Channels      map[EndpointDLPChannel]EndpointChannelConfig `json:"channels,omitempty"`
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
	policy := EndpointDLPPolicy{
		SchemaVersion: EndpointSchemaVersion,
		Target:        repository.PolicyBundleTargetEndpoint,
		Domain:        endpointDomain,
		Rules:         compileEndpointRules(policies),
		Channels:      channels,
	}
	if err := ValidateEndpointPolicy(policy); err != nil {
		return nil, err
	}
	return json.Marshal(policy)
}

// compileEndpointRules flattens a set of policies into endpoint
// rules. A policy with N rules yields N endpoint rules, each tagged
// with a stable `<policy-id>:<index>` id so the agent's audit trail
// can attribute a match back to the source policy.
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
			rules = append(rules, EndpointDLPRule{
				ID:          fmt.Sprintf("%s:%d", p.ID, i),
				Name:        p.Name,
				PatternType: r.Type,
				PatternData: endpointPatternData(r),
				Severity:    endpointSeverity(p.Action),
				Action:      endpointAction(p.Action),
				// Web/SaaS policies are not channel-scoped, so each
				// rule applies to every endpoint channel (empty list
				// = all channels in sng-dlp).
				Channels: []EndpointDLPChannel{},
			})
		}
	}
	return rules
}

// endpointPatternData extracts the mechanism-specific payload sng-dlp
// expects. MIP-label rules carry the label id in Pattern, falling
// back to SensitivityLevel; every other rule type carries its raw
// payload (regex source, keyword dictionary, fingerprint hex) in
// Pattern.
func endpointPatternData(r repository.DLPRule) string {
	if r.Type == repository.DLPRuleTypeMIPLabel && r.Pattern == "" {
		return r.SensitivityLevel
	}
	return r.Pattern
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
	return nil
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
