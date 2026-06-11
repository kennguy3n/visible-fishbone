// Package memory is a thread-safe in-memory implementation of the
// repository interfaces. It exists so service-layer code (in
// internal/service/) can be unit-tested without spinning up Postgres.
//
// The implementation is deliberately simple — it favours
// correctness over performance because the only consumers are
// tests. Tenant isolation is enforced by filtering on tenant_id
// in every method, mirroring what Postgres RLS does in
// production.
//
// Cursor pagination is implemented by sorting the matching rows
// and slicing after the cursor offset. The cursor is a small
// JSON blob containing the last-seen sort-key — opaque to callers
// per the interface contract.
package memory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Store is the aggregate in-memory backend. One Store instance is
// the equivalent of one Postgres database — share it between
// repository constructors in tests.
type Store struct {
	mu sync.RWMutex

	// Top-level tenant table (no tenant-scope).
	tenants map[uuid.UUID]repository.Tenant

	// Tenant-scoped tables. Keys are the row id.
	sites             map[uuid.UUID]repository.Site
	users             map[uuid.UUID]repository.User
	devices           map[uuid.UUID]repository.Device
	claimTokens       map[uuid.UUID]repository.ClaimToken
	auditEntries      map[uuid.UUID]repository.AuditEntry
	policyGraphs      map[uuid.UUID]repository.PolicyGraph
	policyBundles     map[uuid.UUID]repository.PolicyBundle
	policySigningKeys map[uuid.UUID]repository.PolicySigningKey
	policyRollouts    map[uuid.UUID]repository.PolicyRollout
	baselineModels    map[uuid.UUID]repository.BaselineModel
	alerts            map[uuid.UUID]repository.Alert
	alertSuppressions map[uuid.UUID]repository.AlertSuppression
	alertFeedback     map[uuid.UUID]repository.AlertFeedback
	tenantAPIKeys     map[uuid.UUID]repository.TenantAPIKey
	webhookEndpoints  map[uuid.UUID]repository.WebhookEndpoint
	webhookDeliveries map[uuid.UUID]repository.WebhookDelivery

	// Integration connector tables — see migration 014. The shape
	// mirrors webhook_{endpoints,deliveries} deliberately; the
	// dispatcher's ListPending / atomic-claim semantics are the
	// same modulo the connector_id foreign key.
	integrationConnectors map[uuid.UUID]repository.IntegrationConnector
	integrationDeliveries map[uuid.UUID]repository.IntegrationDelivery

	// MSP hierarchy tables — see migration 015. `msps` is the
	// top-level catalog (NOT tenant-scoped, mirrors `tenants`).
	// `mspTenants` is the many-to-many MSP <-> tenant binding;
	// the key is the composite (msp_id, tenant_id) matching the
	// Postgres PRIMARY KEY.
	msps       map[uuid.UUID]repository.MSP
	mspTenants map[mspTenantKey]repository.MSPTenantBinding

	// Device enrollment tables — see migration 017.
	deviceEnrollments  map[deviceEnrollmentKey]repository.DeviceEnrollment
	deviceCertificates map[uuid.UUID]repository.DeviceCertificate

	// CASB tables — see migration 016.
	casbConnectors     map[uuid.UUID]repository.CASBConnector
	casbDiscoveredApps map[uuid.UUID]repository.CASBDiscoveredApp
	casbPostureChecks  map[uuid.UUID]repository.CASBPostureCheck

	// Inline-CASB rules — see migration 037.
	inlineCASBRules map[uuid.UUID]repository.InlineCASBRule

	// Sandbox verdicts — see migration 042.
	sandboxVerdicts map[uuid.UUID]repository.SandboxVerdict

	// IPS per-tenant rule category overrides + daily hit stats —
	// see migration 050. Keyed by (tenant, category) and
	// (tenant, category, yyyy-mm-dd) respectively.
	ipsRuleCategories    map[string]repository.IPSRuleCategorySelection
	ipsRuleCategoryStats map[string]repository.IPSRuleCategoryDailyStat

	// RBI sessions — see migration 043.
	rbiSessions map[uuid.UUID]repository.RBISession

	// RBI session artifacts — see migration 048.
	rbiArtifacts map[uuid.UUID]repository.RBIArtifact

	// App registry tables — see internal/repository/app_registry.go
	// and migrations/008_app_registry.up.sql. `appRegistry` is the
	// global curated catalog (not tenant-scoped); `appOverrides`
	// is the per-tenant overrides table (tenant_id stored on each
	// row so we can filter by tenant just like Postgres RLS).
	appRegistry  map[uuid.UUID]repository.AppRegistry
	appOverrides map[uuid.UUID]repository.AppRegistryOverride

	// Browser protection policies — Phase 4, Task 43.
	browserPolicies map[uuid.UUID]repository.BrowserPolicy

	// Data classification taxonomy — Phase 4, Task 46.
	dataClassifications map[uuid.UUID]repository.DataClassification

	// DLP tables — see migration 019. All tenant-scoped.
	dlpPolicies     map[uuid.UUID]repository.DLPPolicy
	dlpFingerprints map[uuid.UUID]repository.DLPFingerprint
	dlpMatches      map[uuid.UUID]repository.DLPMatch
	// DLP ML model registry — see migration 049. dlpModelAssign maps
	// a tenant to its single active model version.
	dlpModels      map[uuid.UUID]repository.DLPModel
	dlpModelAssign map[uuid.UUID]uuid.UUID

	// AI suggestion tables — see migration 026.
	aiSuggestions map[uuid.UUID]repository.AISuggestion

	// Troubleshooting tables — see migrations 032-033.
	kbEntries            map[uuid.UUID]repository.KBEntry
	troubleshootSessions map[uuid.UUID]repository.TroubleshootSession

	// Role / user_role tables. Roles are NOT tenant-scoped on
	// their own (system roles have TenantID nil).
	roles     map[uuid.UUID]repository.Role
	userRoles map[userRoleKey]repository.UserRole

	// AI correlation tables — see migration 029.
	aiCorrelations map[uuid.UUID]repository.AICorrelation

	// Compliance reports — see migration 022.
	complianceReports map[uuid.UUID]repository.ComplianceReport

	// Compliance evidence — see migration 039. Platform-level
	// (not tenant-scoped).
	complianceEvidence map[uuid.UUID]repository.ComplianceEvidence

	// Playbook tables — see migrations 023-025.
	playbooks           map[uuid.UUID]repository.Playbook
	playbookExecutions  map[uuid.UUID]repository.PlaybookExecution
	playbookStepResults map[uuid.UUID]repository.StepResult
	playbookApprovals   map[uuid.UUID]repository.PlaybookApproval

	// Operational health tables — see migrations 030, 031.
	policyReviewSchedules map[uuid.UUID]repository.PolicyReviewSchedule
	opsHealthSnapshots    map[uuid.UUID]repository.OpsHealthSnapshot

	// IdP federation configs — see migration 034. Tenant-scoped.
	idpConfigs map[uuid.UUID]repository.IDPConfig

	// Device ↔ iam-core identity bindings — see migration 044.
	// Keyed by (tenant_id, device_id) to mirror the Postgres unique
	// index uq_device_identity_bindings_tenant_device.
	deviceIdentityBindings map[deviceBindingKey]repository.DeviceIdentityBinding

	// Residency enforcement audit trail — see migration 046.
	// Tenant-scoped; append-only record of fail-closed rejections.
	residencyAudit map[uuid.UUID]repository.ResidencyAuditEntry

	// Cross-region tenant migration state machine — see migration 059.
	// Tenant-scoped; resumable + rollback-able. Keyed by migration id.
	tenantMigrations map[uuid.UUID]repository.TenantMigration

	// Threat-intel IOC snapshot — see migration 051. A single
	// global whole-set snapshot (not tenant-scoped), so it is held
	// as a flat slice replaced atomically by ReplaceAll.
	threatIOCs []repository.ThreatIOC

	// clock is injected for deterministic tests. Defaults to
	// time.Now.UTC.
	clock func() time.Time
}

// userRoleKey is the composite key for user_roles. Matches the
// Postgres PRIMARY KEY (user_id, role_id, scope_id_coalesced) so
// the memory store has the same uniqueness semantics.
type userRoleKey struct {
	UserID  uuid.UUID
	RoleID  uuid.UUID
	ScopeID uuid.UUID
}

// mspTenantKey is the composite key for msp_tenants. Matches the
// Postgres PRIMARY KEY (msp_id, tenant_id).
type mspTenantKey struct {
	MSPID    uuid.UUID
	TenantID uuid.UUID
}

// deviceBindingKey is the composite key for device_identity_bindings.
// Matches the Postgres unique index (tenant_id, device_id).
type deviceBindingKey struct {
	TenantID uuid.UUID
	DeviceID uuid.UUID
}

// NewStore constructs an empty Store backed by `time.Now().UTC()`.
func NewStore() *Store {
	return &Store{
		tenants:                map[uuid.UUID]repository.Tenant{},
		sites:                  map[uuid.UUID]repository.Site{},
		users:                  map[uuid.UUID]repository.User{},
		devices:                map[uuid.UUID]repository.Device{},
		claimTokens:            map[uuid.UUID]repository.ClaimToken{},
		auditEntries:           map[uuid.UUID]repository.AuditEntry{},
		policyGraphs:           map[uuid.UUID]repository.PolicyGraph{},
		policyBundles:          map[uuid.UUID]repository.PolicyBundle{},
		policySigningKeys:      map[uuid.UUID]repository.PolicySigningKey{},
		policyRollouts:         map[uuid.UUID]repository.PolicyRollout{},
		baselineModels:         map[uuid.UUID]repository.BaselineModel{},
		alerts:                 map[uuid.UUID]repository.Alert{},
		alertSuppressions:      map[uuid.UUID]repository.AlertSuppression{},
		alertFeedback:          map[uuid.UUID]repository.AlertFeedback{},
		tenantAPIKeys:          map[uuid.UUID]repository.TenantAPIKey{},
		webhookEndpoints:       map[uuid.UUID]repository.WebhookEndpoint{},
		webhookDeliveries:      map[uuid.UUID]repository.WebhookDelivery{},
		integrationConnectors:  map[uuid.UUID]repository.IntegrationConnector{},
		integrationDeliveries:  map[uuid.UUID]repository.IntegrationDelivery{},
		msps:                   map[uuid.UUID]repository.MSP{},
		casbConnectors:         map[uuid.UUID]repository.CASBConnector{},
		inlineCASBRules:        map[uuid.UUID]repository.InlineCASBRule{},
		sandboxVerdicts:        map[uuid.UUID]repository.SandboxVerdict{},
		ipsRuleCategories:      map[string]repository.IPSRuleCategorySelection{},
		ipsRuleCategoryStats:   map[string]repository.IPSRuleCategoryDailyStat{},
		rbiSessions:            map[uuid.UUID]repository.RBISession{},
		rbiArtifacts:           map[uuid.UUID]repository.RBIArtifact{},
		casbDiscoveredApps:     map[uuid.UUID]repository.CASBDiscoveredApp{},
		casbPostureChecks:      map[uuid.UUID]repository.CASBPostureCheck{},
		mspTenants:             map[mspTenantKey]repository.MSPTenantBinding{},
		deviceEnrollments:      map[deviceEnrollmentKey]repository.DeviceEnrollment{},
		deviceCertificates:     map[uuid.UUID]repository.DeviceCertificate{},
		appRegistry:            map[uuid.UUID]repository.AppRegistry{},
		appOverrides:           map[uuid.UUID]repository.AppRegistryOverride{},
		browserPolicies:        map[uuid.UUID]repository.BrowserPolicy{},
		dataClassifications:    map[uuid.UUID]repository.DataClassification{},
		dlpPolicies:            map[uuid.UUID]repository.DLPPolicy{},
		dlpFingerprints:        map[uuid.UUID]repository.DLPFingerprint{},
		dlpMatches:             map[uuid.UUID]repository.DLPMatch{},
		dlpModels:              map[uuid.UUID]repository.DLPModel{},
		dlpModelAssign:         map[uuid.UUID]uuid.UUID{},
		aiSuggestions:          map[uuid.UUID]repository.AISuggestion{},
		kbEntries:              map[uuid.UUID]repository.KBEntry{},
		troubleshootSessions:   map[uuid.UUID]repository.TroubleshootSession{},
		roles:                  map[uuid.UUID]repository.Role{},
		userRoles:              map[userRoleKey]repository.UserRole{},
		aiCorrelations:         map[uuid.UUID]repository.AICorrelation{},
		complianceReports:      map[uuid.UUID]repository.ComplianceReport{},
		complianceEvidence:     map[uuid.UUID]repository.ComplianceEvidence{},
		playbooks:              map[uuid.UUID]repository.Playbook{},
		playbookExecutions:     map[uuid.UUID]repository.PlaybookExecution{},
		playbookStepResults:    map[uuid.UUID]repository.StepResult{},
		playbookApprovals:      map[uuid.UUID]repository.PlaybookApproval{},
		policyReviewSchedules:  map[uuid.UUID]repository.PolicyReviewSchedule{},
		opsHealthSnapshots:     map[uuid.UUID]repository.OpsHealthSnapshot{},
		idpConfigs:             map[uuid.UUID]repository.IDPConfig{},
		deviceIdentityBindings: map[deviceBindingKey]repository.DeviceIdentityBinding{},
		residencyAudit:         map[uuid.UUID]repository.ResidencyAuditEntry{},
		tenantMigrations:       map[uuid.UUID]repository.TenantMigration{},
		clock:                  func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall-clock source. Tests use this to assert
// deterministic CreatedAt / UpdatedAt timestamps.
func (s *Store) SetClock(fn func() time.Time) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = fn
}

// scopeIDOrZero collapses a nil scope_id to the zero-UUID for
// user_role lookup, matching the Postgres COALESCE behaviour.
func scopeIDOrZero(p *uuid.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return *p
}

// isJSONNullLiteral returns true when `b` is the JSON `null` token
// (after stripping surrounding whitespace). Round-22 of Devin Review
// on PR #42 (ANALYSIS_0005) flagged that `{"settings": null}` decodes
// to `json.RawMessage("null")` — len == 4, not 0 — and therefore
// bypasses every `len(payload) == 0` default that the repository
// boundary uses to enforce the OpenAPI declaration `settings: type:
// object`. Treat the literal `null` as equivalent to absent so the
// stored column is always a JSON object. The matching helper on the
// postgres backend lives in internal/repository/postgres/nulls.go.
func isJSONNullLiteral(b json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(b), []byte("null"))
}

// cloneJSON returns a deep copy of a json.RawMessage so callers
// cannot mutate stored bytes.
func cloneJSON(in json.RawMessage) json.RawMessage {
	if in == nil {
		return nil
	}
	out := make(json.RawMessage, len(in))
	copy(out, in)
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// encodeCursor renders a sort-key into the opaque base64-encoded
// JSON cursor returned by List operations. The shape is private —
// callers MUST NOT decode it.
type cursor struct {
	// CreatedAt is the canonical sort key for time-ordered lists.
	CreatedAt time.Time `json:"t,omitempty"`
	// ID is appended for tie-breaking when CreatedAt collides
	// (relevant for high-throughput audit-log inserts).
	ID uuid.UUID `json:"i,omitempty"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	if s == "" {
		return cursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	var c cursor
	if err := json.Unmarshal(b, &c); err != nil {
		return cursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	return c, nil
}

// orderBefore reports whether a < b under the given order. ASC means
// "earlier comes first", DESC means "later comes first" — and the
// cursor is the boundary; rows strictly past it are included.
func orderBefore(a, b cursor, order repository.SortOrder) bool {
	if order == repository.SortAsc {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID.String(), b.ID.String()) < 0
		}
		return a.CreatedAt.Before(b.CreatedAt)
	}
	// DESC default.
	if a.CreatedAt.Equal(b.CreatedAt) {
		return strings.Compare(a.ID.String(), b.ID.String()) > 0
	}
	return a.CreatedAt.After(b.CreatedAt)
}

// paginate is a generic helper: given a slice already sorted in the
// desired display order, return up to page.Limit items starting
// strictly past the cursor and the cursor for the next page.
func paginate[T any](items []T, page repository.Page, keyOf func(T) cursor) repository.PageResult[T] {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		// Treat bad cursors as "start over". The interface
		// docs say cursors are opaque, so the only way a
		// caller hits this is by either replaying a stale
		// cursor or crafting one — neither warrants an error
		// in the memory driver. Postgres driver returns an
		// invalid-argument error for safety.
		cur = cursor{}
	}
	out := make([]T, 0, page.Limit)
	skipping := page.After != ""
	for _, it := range items {
		k := keyOf(it)
		if skipping {
			// Skip until we're strictly past the cursor's
			// position in display order. orderBefore(cur, k)
			// is true when k comes after cur in display
			// order. The memory store's display order is
			// the slice order, so we use a forward scan.
			if !orderBefore(cur, k, page.Order) {
				continue
			}
			skipping = false
		}
		out = append(out, it)
		if len(out) >= page.Limit {
			break
		}
	}
	next := ""
	if len(out) == page.Limit && len(items) > 0 {
		// Only emit a non-empty cursor if there might be more
		// data. If we filled the page exactly with the tail,
		// the next call will return an empty page — that's
		// fine.
		next = encodeCursor(keyOf(out[len(out)-1]))
	}
	return repository.PageResult[T]{Items: out, NextCursor: next}
}

// sortByCreatedAtDesc returns a copy of items sorted by CreatedAt
// descending, with id as the tie-breaker. Used by every "time-
// ordered" List operation.
func sortByCreatedAtDesc[T any](items []T, ts func(T) time.Time, id func(T) uuid.UUID, order repository.SortOrder) []T {
	out := make([]T, len(items))
	copy(out, items)
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := ts(out[i]), ts(out[j])
		if !ti.Equal(tj) {
			if order == repository.SortAsc {
				return ti.Before(tj)
			}
			return ti.After(tj)
		}
		// Stable tie-break by id.
		if order == repository.SortAsc {
			return strings.Compare(id(out[i]).String(), id(out[j]).String()) < 0
		}
		return strings.Compare(id(out[i]).String(), id(out[j]).String()) > 0
	})
	return out
}

// errCtxIfNeeded returns the context's error wrapped through the
// repository sentinels so callers can `errors.Is` for either side.
// In practice the memory driver is in-process and never sees a
// cancelled context past the function boundary, but checking up
// front lets tests verify the contract.
func errCtxIfNeeded(ctx context.Context) error {
	return ctx.Err()
}
