package casb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// Inline CASB upgrades the API-mode discovery in this package
// (service.go) to *inline*, real-time inspection in the SWG
// ext-authz path. Where the API-mode service polls SaaS provider
// APIs out-of-band, the inline service manages per-tenant rules
// that the policy compiler folds into the SWG slice of a signed
// policy bundle; the edge / cloud data plane
// (crates/sng-swg/src/casb.rs) decodes that slice and enforces it
// on live traffic.
//
// Wire contract with the Rust data plane
// ---------------------------------------
// CompileRules emits []policy.Rule with Domain == DomainInlineCASB.
// Each compiled rule carries the CASB payload in its Extra under
// the "casb" key, shaped exactly like the Rust `CasbRule`
// (crates/sng-swg/src/casb_rules.rs):
//
//	{"id","app_id","action","verdict","conditions":{...},"priority"}
//
// so the SWG bundle decoder can reconstruct the inspector's rule
// set without a second schema. Keeping the inline-CASB rules as
// first-class policy.Rule entries means they ride the same
// signing, versioning, and CompileTarget routing as every other
// SWG rule (graph.go routes DomainInlineCASB to the edge + cloud
// targets, identically to DomainSWG).

// InlineAction is the SaaS request action an inline rule gates. It
// mirrors crate sng-swg's CasbAction.
type InlineAction string

const (
	InlineActionUpload   InlineAction = "upload"
	InlineActionDownload InlineAction = "download"
	InlineActionShare    InlineAction = "share"
	InlineActionDelete   InlineAction = "delete"

	// WS4 inline-CASB expansion. These mirror the additional
	// crate sng-swg CasbAction variants (casb_rules.rs); the
	// string forms MUST stay byte-identical across the Go control
	// plane and the Rust data plane or compiled bundles fail to
	// match at the edge.
	InlineActionLogin             InlineAction = "login"
	InlineActionAdminConfigChange InlineAction = "admin_config_change"
	InlineActionAPIKeyCreate      InlineAction = "api_key_create"
	InlineActionExternalShare     InlineAction = "external_share"
	InlineActionBulkExport        InlineAction = "bulk_export"
)

// IsValid reports whether the action is one of the known verbs.
func (a InlineAction) IsValid() bool {
	switch a {
	case InlineActionUpload, InlineActionDownload, InlineActionShare, InlineActionDelete,
		InlineActionLogin, InlineActionAdminConfigChange, InlineActionAPIKeyCreate,
		InlineActionExternalShare, InlineActionBulkExport:
		return true
	}
	return false
}

// InlineVerdict is the decision an inline rule applies on match. It
// mirrors crate sng-swg's CasbVerdict.
type InlineVerdict string

const (
	InlineVerdictAllow InlineVerdict = "allow"
	InlineVerdictBlock InlineVerdict = "block"
	InlineVerdictLog   InlineVerdict = "log"
)

// IsValid reports whether the verdict is one of the known values.
func (v InlineVerdict) IsValid() bool {
	switch v {
	case InlineVerdictAllow, InlineVerdictBlock, InlineVerdictLog:
		return true
	}
	return false
}

// verb maps an inline-CASB verdict onto the policy graph Verb the
// compiled rule carries. block→deny, log→log, allow→allow keeps
// the bundle's verb column meaningful to tooling that does not
// understand the CASB payload.
func (v InlineVerdict) verb() policy.Verb {
	switch v {
	case InlineVerdictBlock:
		return policy.VerbDeny
	case InlineVerdictLog:
		return policy.VerbLog
	default:
		return policy.VerbAllow
	}
}

// AnyApp is the wildcard app id: a rule with AppID == AnyApp
// applies to every configured SaaS app. Matches the Rust
// inspector's "*" wildcard.
const AnyApp = "*"

// knownApps is the set of SaaS app ids the inline inspector can
// detect, plus the AnyApp wildcard. Every id here MUST have a
// matching AppSignature in the data-plane catalog
// (crates/sng-swg/src/casb.rs AppCatalog::builtin) — the control
// plane validates a rule's app_id against this set, and the edge
// resolves the same id to a detection signature. The two lists are
// kept byte-identical so a rule an operator can create is a rule the
// edge can actually enforce; an id present here but absent in the
// Rust catalog would compile into a bundle that silently never
// matches at the edge.
//
// The ids mirror the canonical app ids used by the data-plane
// catalog and the repository.CASBConnectorType values (e.g. "box",
// "aws_console"). "google_workspace" intentionally keeps the
// data-plane spelling rather than the connector type's "google".
var knownApps = map[string]struct{}{
	// Launch apps.
	"m365":             {},
	"google_workspace": {},
	"slack":            {},
	"salesforce":       {},
	// Catalog expansion: cloud storage, code, ITSM/CRM/support,
	// conferencing/collaboration, cloud consoles, identity, and HCM.
	"box":          {},
	"dropbox":      {},
	"github":       {},
	"gitlab":       {},
	"jira":         {},
	"confluence":   {},
	"servicenow":   {},
	"zendesk":      {},
	"hubspot":      {},
	"zoom":         {},
	"teams":        {},
	"aws_console":  {},
	"gcp_console":  {},
	"azure_portal": {},
	"okta":         {},
	"workday":      {},
	// Wildcard: a rule that applies to every configured app.
	AnyApp: {},
}

// KnownApps returns the sorted set of SaaS app ids the inline
// inspector recognises, excluding the AnyApp wildcard. It lets the
// API surface and tooling enumerate the catalog without exposing the
// internal map (and without the caller having to special-case the
// wildcard). The returned slice is freshly allocated, so callers may
// mutate it freely.
func KnownApps() []string {
	apps := make([]string, 0, len(knownApps))
	for app := range knownApps {
		if app == AnyApp {
			continue
		}
		apps = append(apps, app)
	}
	sort.Strings(apps)
	return apps
}

// InlineConditions narrows when a rule fires. All fields are
// optional; a zero value means "do not constrain on this
// dimension". The JSON shape matches the Rust CasbConditions.
type InlineConditions struct {
	// FileType is a file extension (without the dot, e.g. "docx"),
	// compared case-insensitively. Empty means any file type.
	FileType string `json:"file_type,omitempty"`
	// SizeThreshold is the minimum content length in bytes; the
	// rule matches a request whose size is >= this value. Zero
	// means any size.
	SizeThreshold int64 `json:"size_threshold,omitempty"`
	// LabelMatch is a sensitivity label the request must carry,
	// compared case-insensitively. Empty means any label.
	LabelMatch string `json:"label_match,omitempty"`
}

// normalize trims and lowercases the string conditions so the
// stored shape matches what the data plane compares against.
func (c *InlineConditions) normalize() {
	c.FileType = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c.FileType), "."))
	c.LabelMatch = strings.TrimSpace(c.LabelMatch)
}

// validate rejects nonsensical conditions.
func (c InlineConditions) validate() error {
	if c.SizeThreshold < 0 {
		return fmt.Errorf("%w: size_threshold must be non-negative", ErrInvalidArgument)
	}
	return nil
}

// InlineRule is a per-tenant inline-CASB rule. It is the
// control-plane row behind migration 037 (inline_casb_rules).
type InlineRule struct {
	ID         uuid.UUID        `json:"id"`
	TenantID   uuid.UUID        `json:"tenant_id"`
	AppID      string           `json:"app_id"`
	Action     InlineAction     `json:"action"`
	Verdict    InlineVerdict    `json:"verdict"`
	Conditions InlineConditions `json:"conditions"`
	Enabled    bool             `json:"enabled"`
	// Priority is int32 to match the Postgres INTEGER column
	// (037_inline_casb.up.sql) and the Rust data plane's i32
	// (crates/sng-swg/src/casb_rules.rs); a wider type would let a
	// value past i32::MAX persist in-memory and then fail bundle
	// deserialisation on the data plane.
	Priority  int32     `json:"priority"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// InlineRuleStore is the persistence port for inline-CASB rules.
// A Postgres-backed implementation lands against the
// inline_casb_rules table (migration 037, RLS-scoped to
// sng.tenant_id); NewInMemoryInlineRuleStore provides an
// equivalent, tenant-isolated in-memory implementation used by the
// service's tests and by deployments that have not yet wired the
// SQL repository.
type InlineRuleStore interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]InlineRule, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (InlineRule, error)
	Create(ctx context.Context, tenantID uuid.UUID, rule InlineRule) (InlineRule, error)
	Update(ctx context.Context, tenantID uuid.UUID, rule InlineRule) (InlineRule, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}

// InlineCASBService manages inline-CASB rules per tenant and
// compiles them into the SWG policy-bundle slice.
type InlineCASBService struct {
	store   InlineRuleStore
	audit   repository.AuditLogRepository
	logger  *slog.Logger
	nowFunc func() time.Time
	newID   func() uuid.UUID
}

// NewInline constructs an inline-CASB service. audit may be nil
// (audit logging is then skipped). store is required.
func NewInline(
	store InlineRuleStore,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *InlineCASBService {
	if logger == nil {
		logger = slog.Default()
	}
	return &InlineCASBService{
		store:   store,
		audit:   audit,
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
		newID:   uuid.New,
	}
}

// SetClock overrides the wall clock for tests.
func (svc *InlineCASBService) SetClock(f func() time.Time) { svc.nowFunc = f }

// SetIDGenerator overrides the id generator for tests.
func (svc *InlineCASBService) SetIDGenerator(f func() uuid.UUID) { svc.newID = f }

// CreateInlineRuleInput is the validated input to CreateInlineRule.
type CreateInlineRuleInput struct {
	AppID      string
	Action     InlineAction
	Verdict    InlineVerdict
	Conditions InlineConditions
	Enabled    bool
	Priority   int32
}

func (in CreateInlineRuleInput) validate() error {
	app := strings.ToLower(strings.TrimSpace(in.AppID))
	if app == "" {
		return fmt.Errorf("%w: app_id is required", ErrInvalidArgument)
	}
	if _, ok := knownApps[app]; !ok {
		return fmt.Errorf("%w: unknown app_id %q", ErrInvalidArgument, in.AppID)
	}
	if !in.Action.IsValid() {
		return fmt.Errorf("%w: invalid action %q", ErrInvalidArgument, in.Action)
	}
	if !in.Verdict.IsValid() {
		return fmt.Errorf("%w: invalid verdict %q", ErrInvalidArgument, in.Verdict)
	}
	return in.Conditions.validate()
}

// CreateInlineRule validates and persists a new inline-CASB rule.
func (svc *InlineCASBService) CreateInlineRule(
	ctx context.Context,
	tenantID uuid.UUID,
	in CreateInlineRuleInput,
	actorID *uuid.UUID,
) (InlineRule, error) {
	if err := in.validate(); err != nil {
		return InlineRule{}, err
	}
	conds := in.Conditions
	conds.normalize()
	now := svc.nowFunc()
	rule := InlineRule{
		ID:         svc.newID(),
		TenantID:   tenantID,
		AppID:      strings.ToLower(strings.TrimSpace(in.AppID)),
		Action:     in.Action,
		Verdict:    in.Verdict,
		Conditions: conds,
		Enabled:    in.Enabled,
		Priority:   in.Priority,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	created, err := svc.store.Create(ctx, tenantID, rule)
	if err != nil {
		return InlineRule{}, err
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.inline_rule_created", &created.ID, map[string]any{
		"app_id":  created.AppID,
		"action":  string(created.Action),
		"verdict": string(created.Verdict),
	})
	return created, nil
}

// UpdateInlineRuleInput is the partial-update payload. Nil pointers
// leave the corresponding field unchanged.
type UpdateInlineRuleInput struct {
	AppID      *string
	Action     *InlineAction
	Verdict    *InlineVerdict
	Conditions *InlineConditions
	Enabled    *bool
	Priority   *int32
}

// UpdateInlineRule applies a partial update to an existing rule.
func (svc *InlineCASBService) UpdateInlineRule(
	ctx context.Context,
	tenantID, id uuid.UUID,
	in UpdateInlineRuleInput,
	actorID *uuid.UUID,
) (InlineRule, error) {
	existing, err := svc.store.Get(ctx, tenantID, id)
	if err != nil {
		return InlineRule{}, err
	}
	if in.AppID != nil {
		app := strings.ToLower(strings.TrimSpace(*in.AppID))
		if _, ok := knownApps[app]; !ok {
			return InlineRule{}, fmt.Errorf("%w: unknown app_id %q", ErrInvalidArgument, *in.AppID)
		}
		existing.AppID = app
	}
	if in.Action != nil {
		if !in.Action.IsValid() {
			return InlineRule{}, fmt.Errorf("%w: invalid action %q", ErrInvalidArgument, *in.Action)
		}
		existing.Action = *in.Action
	}
	if in.Verdict != nil {
		if !in.Verdict.IsValid() {
			return InlineRule{}, fmt.Errorf("%w: invalid verdict %q", ErrInvalidArgument, *in.Verdict)
		}
		existing.Verdict = *in.Verdict
	}
	if in.Conditions != nil {
		conds := *in.Conditions
		conds.normalize()
		if err := conds.validate(); err != nil {
			return InlineRule{}, err
		}
		existing.Conditions = conds
	}
	if in.Enabled != nil {
		existing.Enabled = *in.Enabled
	}
	if in.Priority != nil {
		existing.Priority = *in.Priority
	}
	existing.UpdatedAt = svc.nowFunc()
	updated, err := svc.store.Update(ctx, tenantID, existing)
	if err != nil {
		return InlineRule{}, err
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.inline_rule_updated", &updated.ID, map[string]any{
		"app_id":  updated.AppID,
		"action":  string(updated.Action),
		"verdict": string(updated.Verdict),
		"enabled": updated.Enabled,
	})
	return updated, nil
}

// GetInlineRule returns a single inline rule.
func (svc *InlineCASBService) GetInlineRule(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (InlineRule, error) {
	return svc.store.Get(ctx, tenantID, id)
}

// ListInlineRules returns all inline rules for a tenant, ordered by
// descending priority then id for a deterministic listing.
func (svc *InlineCASBService) ListInlineRules(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]InlineRule, error) {
	rules, err := svc.store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sortRules(rules)
	return rules, nil
}

// DeleteInlineRule removes an inline rule.
func (svc *InlineCASBService) DeleteInlineRule(
	ctx context.Context,
	tenantID, id uuid.UUID,
	actorID *uuid.UUID,
) error {
	if err := svc.store.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.inline_rule_deleted", &id, nil)
	return nil
}

// casbBundlePayload is the JSON shape carried in a compiled rule's
// Extra["casb"], matching the Rust CasbRule.
type casbBundlePayload struct {
	ID         string           `json:"id"`
	AppID      string           `json:"app_id"`
	Action     InlineAction     `json:"action"`
	Verdict    InlineVerdict    `json:"verdict"`
	Conditions InlineConditions `json:"conditions"`
	Priority   int32            `json:"priority"`
}

// CompileRules loads a tenant's enabled inline-CASB rules and
// compiles them into policy.Rule entries tagged with
// DomainInlineCASB, ready to be merged into the policy graph's
// rule slice. Disabled rules are skipped. The returned rules are
// ordered by descending priority then id so the data-plane scan is
// deterministic. Each rule embeds its CASB payload in Extra["casb"]
// (see the wire-contract note at the top of this file).
func (svc *InlineCASBService) CompileRules(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]policy.Rule, error) {
	all, err := svc.store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	enabled := make([]InlineRule, 0, len(all))
	for _, r := range all {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	sortRules(enabled)
	out := make([]policy.Rule, 0, len(enabled))
	for _, r := range enabled {
		compiled, err := r.toPolicyRule()
		if err != nil {
			return nil, err
		}
		out = append(out, compiled)
	}
	return out, nil
}

// toPolicyRule converts an inline rule into a policy.Rule carrying
// the CASB payload in Extra.
func (r InlineRule) toPolicyRule() (policy.Rule, error) {
	payload := casbBundlePayload{
		ID:         r.ID.String(),
		AppID:      r.AppID,
		Action:     r.Action,
		Verdict:    r.Verdict,
		Conditions: r.Conditions,
		Priority:   r.Priority,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return policy.Rule{}, fmt.Errorf("marshal casb payload: %w", err)
	}
	return policy.Rule{
		ID:          r.ID.String(),
		Domain:      policy.DomainInlineCASB,
		Verb:        r.Verdict.verb(),
		Description: fmt.Sprintf("inline casb: %s %s on %s", r.Verdict, r.Action, r.AppID),
		Extra: map[string]json.RawMessage{
			"casb": raw,
		},
	}, nil
}

// DefaultTemplates returns the starter inline-CASB rules an
// operator can seed a tenant with. These encode the two reference
// policies from the product spec.
func DefaultTemplates() []CreateInlineRuleInput {
	return []CreateInlineRuleInput{
		{
			// "block public sharing on OneDrive"
			AppID:    "m365",
			Action:   InlineActionShare,
			Verdict:  InlineVerdictBlock,
			Enabled:  true,
			Priority: 100,
		},
		{
			// "log all uploads > 10MB to Salesforce"
			AppID:   "salesforce",
			Action:  InlineActionUpload,
			Verdict: InlineVerdictLog,
			Conditions: InlineConditions{
				SizeThreshold: 10 * 1024 * 1024,
			},
			Enabled:  true,
			Priority: 50,
		},
	}
}

// SeedDefaultTemplates creates the DefaultTemplates rules for a
// tenant that has none yet. It is a no-op (returning the existing
// rules) when the tenant already has inline rules, so it is safe to
// call on every tenant bootstrap.
func (svc *InlineCASBService) SeedDefaultTemplates(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
) ([]InlineRule, error) {
	existing, err := svc.store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		sortRules(existing)
		return existing, nil
	}
	created := make([]InlineRule, 0, len(DefaultTemplates()))
	for _, tmpl := range DefaultTemplates() {
		rule, err := svc.CreateInlineRule(ctx, tenantID, tmpl, actorID)
		if err != nil {
			return nil, err
		}
		created = append(created, rule)
	}
	return created, nil
}

func sortRules(rules []InlineRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority > rules[j].Priority
		}
		return rules[i].ID.String() < rules[j].ID.String()
	})
}

func (svc *InlineCASBService) logAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action string,
	resourceID *uuid.UUID,
	details map[string]any,
) {
	if svc.audit == nil {
		return
	}
	var detailsJSON json.RawMessage
	if details != nil {
		if b, err := json.Marshal(details); err == nil {
			detailsJSON = b
		}
	}
	entry := repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: "casb_inline_rule",
		ResourceID:   resourceID,
		Details:      detailsJSON,
	}
	if _, err := svc.audit.Append(ctx, tenantID, entry); err != nil {
		svc.logger.Warn("casb: inline audit append failed",
			slog.String("action", action),
			slog.Any("error", err))
	}
}

// InMemoryInlineRuleStore is a tenant-isolated, concurrency-safe
// in-memory InlineRuleStore. It is the default store for tests and
// for deployments that have not yet wired the Postgres repository.
type InMemoryInlineRuleStore struct {
	mu    sync.RWMutex
	rules map[uuid.UUID]map[uuid.UUID]InlineRule
}

// NewInMemoryInlineRuleStore constructs an empty in-memory store.
func NewInMemoryInlineRuleStore() *InMemoryInlineRuleStore {
	return &InMemoryInlineRuleStore{
		rules: make(map[uuid.UUID]map[uuid.UUID]InlineRule),
	}
}

// List returns copies of all rules for a tenant.
func (s *InMemoryInlineRuleStore) List(
	_ context.Context,
	tenantID uuid.UUID,
) ([]InlineRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucket := s.rules[tenantID]
	out := make([]InlineRule, 0, len(bucket))
	for _, r := range bucket {
		out = append(out, r)
	}
	return out, nil
}

// Get returns a single rule scoped to the tenant.
func (s *InMemoryInlineRuleStore) Get(
	_ context.Context,
	tenantID, id uuid.UUID,
) (InlineRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[tenantID][id]
	if !ok {
		return InlineRule{}, ErrNotFound
	}
	return r, nil
}

// Create inserts a new rule, rejecting a duplicate id.
func (s *InMemoryInlineRuleStore) Create(
	_ context.Context,
	tenantID uuid.UUID,
	rule InlineRule,
) (InlineRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rules[tenantID] == nil {
		s.rules[tenantID] = make(map[uuid.UUID]InlineRule)
	}
	if _, exists := s.rules[tenantID][rule.ID]; exists {
		return InlineRule{}, fmt.Errorf("%w: rule %s already exists", ErrInvalidArgument, rule.ID)
	}
	rule.TenantID = tenantID
	s.rules[tenantID][rule.ID] = rule
	return rule, nil
}

// Update replaces an existing rule scoped to the tenant.
func (s *InMemoryInlineRuleStore) Update(
	_ context.Context,
	tenantID uuid.UUID,
	rule InlineRule,
) (InlineRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[tenantID][rule.ID]; !ok {
		return InlineRule{}, ErrNotFound
	}
	rule.TenantID = tenantID
	s.rules[tenantID][rule.ID] = rule
	return rule, nil
}

// Delete removes a rule scoped to the tenant.
func (s *InMemoryInlineRuleStore) Delete(
	_ context.Context,
	tenantID, id uuid.UUID,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[tenantID][id]; !ok {
		return ErrNotFound
	}
	delete(s.rules[tenantID], id)
	return nil
}
