package tenant_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	svctenant "github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// stubAuthz returns a pre-canned authorized tenant list.
type stubAuthz struct {
	tenants []uuid.UUID
	err     error
}

func (s stubAuthz) ListAuthorizedTenants(_ context.Context, _, _ uuid.UUID, _ repository.MSPRepository) ([]uuid.UUID, error) {
	return s.tenants, s.err
}

// stubPolicy implements PolicyTemplateApplier.
type stubPolicy struct {
	inflight atomic.Int64
	maxLive  atomic.Int64

	mu   sync.Mutex
	fail map[uuid.UUID]error
	got  map[uuid.UUID]json.RawMessage
}

func newStubPolicy() *stubPolicy {
	return &stubPolicy{fail: map[uuid.UUID]error{}, got: map[uuid.UUID]json.RawMessage{}}
}

func (s *stubPolicy) PutGraph(_ context.Context, tid uuid.UUID, _ *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	live := s.inflight.Add(1)
	for {
		cur := s.maxLive.Load()
		if live <= cur || s.maxLive.CompareAndSwap(cur, live) {
			break
		}
	}
	defer s.inflight.Add(-1)
	time.Sleep(2 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, ok := s.fail[tid]; ok {
		return repository.PolicyGraph{}, err
	}
	s.got[tid] = append(json.RawMessage{}, raw...)
	return repository.PolicyGraph{TenantID: tid, Version: 7}, nil
}

// stubSites implements SiteProvisioner.
type stubSites struct {
	mu   sync.Mutex
	fail map[uuid.UUID]error
	got  map[uuid.UUID]repository.Site
}

func newStubSites() *stubSites {
	return &stubSites{fail: map[uuid.UUID]error{}, got: map[uuid.UUID]repository.Site{}}
}

func (s *stubSites) Create(_ context.Context, tid uuid.UUID, _ *uuid.UUID, site repository.Site) (repository.Site, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, ok := s.fail[tid]; ok {
		return repository.Site{}, err
	}
	site.ID = uuid.New()
	site.TenantID = tid
	s.got[tid] = site
	return site, nil
}

// stubTokens implements ClaimTokenIssuer.
type stubTokens struct {
	mu         sync.Mutex
	fail       map[uuid.UUID]int // tenantID -> fail-after-Nth call
	calls      map[uuid.UUID]int
	plaintexts map[uuid.UUID][]string
}

func newStubTokens() *stubTokens {
	return &stubTokens{
		fail:       map[uuid.UUID]int{},
		calls:      map[uuid.UUID]int{},
		plaintexts: map[uuid.UUID][]string{},
	}
}

func (s *stubTokens) GenerateClaimToken(_ context.Context, tid uuid.UUID, _ time.Duration, _ *uuid.UUID) (svctenant.ClaimTokenResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[tid]++
	if failAfter, ok := s.fail[tid]; ok && s.calls[tid] > failAfter {
		return svctenant.ClaimTokenResult{}, errors.New("token issue failure")
	}
	pt := uuid.NewString()
	s.plaintexts[tid] = append(s.plaintexts[tid], pt)
	return svctenant.ClaimTokenResult{Plaintext: pt, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestApplyPolicyTemplate_RejectsEmptyTemplate(t *testing.T) {
	t.Parallel()
	svc := svctenant.NewBulkService(nil, stubAuthz{}, newStubPolicy(), nil, nil, nil, svctenant.BulkOptions{})
	if _, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestApplyPolicyTemplate_RequiresPolicyApplier(t *testing.T) {
	t.Parallel()
	svc := svctenant.NewBulkService(nil, stubAuthz{}, nil, nil, nil, nil, svctenant.BulkOptions{})
	if _, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected error when policy applier is nil")
	}
}

func TestApplyPolicyTemplate_FanOutCapturesPartialFailures(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	policy := newStubPolicy()
	policy.fail[tenants[1]] = errors.New("tenant rejected schema")

	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, policy, nil, nil, nil, svctenant.BulkOptions{Concurrency: 4})
	res, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, json.RawMessage(`{"version":1}`))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Total() != 3 || len(res.Successes) != 2 || len(res.Failures) != 1 {
		t.Fatalf("counts wrong: total=%d successes=%d failures=%d", res.Total(), len(res.Successes), len(res.Failures))
	}
	// authorizedTenants sorts by UUID, so the failure ends up at
	// whatever index tenants[1] sorts to. Assert by tenant ID, not
	// slice position.
	if res.Failures[0].TenantID != tenants[1] {
		t.Fatalf("wrong tenant failed: got %v want %v", res.Failures[0].TenantID, tenants[1])
	}
	for _, s := range res.Successes {
		if s.PolicyVersion != 7 {
			t.Fatalf("unexpected version %d for tenant %v", s.PolicyVersion, s.TenantID)
		}
	}
}

func TestApplyPolicyTemplate_RespectsConcurrencyLimit(t *testing.T) {
	t.Parallel()
	const n = 8
	tenants := make([]uuid.UUID, n)
	for i := range tenants {
		tenants[i] = uuid.New()
	}
	policy := newStubPolicy()
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, policy, nil, nil, nil, svctenant.BulkOptions{Concurrency: 2})
	if _, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if peak := policy.maxLive.Load(); peak > 2 {
		t.Fatalf("peak in-flight %d exceeded concurrency cap 2", peak)
	}
}

func TestApplyPolicyTemplate_AuthzErrorPropagates(t *testing.T) {
	t.Parallel()
	svc := svctenant.NewBulkService(nil, stubAuthz{err: errors.New("rbac down")}, newStubPolicy(), nil, nil, nil, svctenant.BulkOptions{})
	_, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error when authz fails")
	}
}

func TestBulkProvisionSites_PerTenantSlugCollisionContained(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New(), uuid.New()}
	sites := newStubSites()
	sites.fail[tenants[0]] = errors.New("slug collision")
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, nil, sites, nil, nil, svctenant.BulkOptions{})
	res, err := svc.BulkProvisionSites(context.Background(), uuid.New(), uuid.New(), nil, repository.Site{Name: "HQ", Template: repository.SiteTemplateBranch})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(res.Failures) != 1 || len(res.Successes) != 1 {
		t.Fatalf("expected 1 success + 1 failure, got %#v", res)
	}
	if res.Successes[0].SiteID == uuid.Nil {
		t.Fatal("success outcome missing SiteID")
	}
}

func TestBulkProvisionSites_TemplateIsClonedPerTenant(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New(), uuid.New()}
	sites := newStubSites()
	tmpl := repository.Site{
		ID:       uuid.New(), // intentionally set; service should clear it
		TenantID: uuid.New(), // ditto
		Name:     "HQ",
		Template: repository.SiteTemplateBranch,
	}
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, nil, sites, nil, nil, svctenant.BulkOptions{})
	if _, err := svc.BulkProvisionSites(context.Background(), uuid.New(), uuid.New(), nil, tmpl); err != nil {
		t.Fatalf("provision: %v", err)
	}
	sites.mu.Lock()
	defer sites.mu.Unlock()
	for tid, got := range sites.got {
		if got.TenantID != tid {
			t.Errorf("tenant %v: got tenant_id=%v", tid, got.TenantID)
		}
		// The template's original ID should not have leaked into
		// the per-tenant create call.
		if got.ID == tmpl.ID && tmpl.ID != uuid.Nil {
			t.Errorf("tenant %v: template ID %v leaked into stored site", tid, tmpl.ID)
		}
	}
}

func TestBulkGenerateClaimTokens_RejectsBadCount(t *testing.T) {
	t.Parallel()
	svc := svctenant.NewBulkService(nil, stubAuthz{}, nil, nil, newStubTokens(), nil, svctenant.BulkOptions{})
	if _, err := svc.BulkGenerateClaimTokens(context.Background(), uuid.New(), uuid.New(), nil, 0, time.Hour); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestBulkGenerateClaimTokens_HappyPath(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New(), uuid.New()}
	tokens := newStubTokens()
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, nil, nil, tokens, nil, svctenant.BulkOptions{})
	res, err := svc.BulkGenerateClaimTokens(context.Background(), uuid.New(), uuid.New(), nil, 3, time.Hour)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(res.Successes) != 2 {
		t.Fatalf("expected 2 successes, got %d", len(res.Successes))
	}
	for _, s := range res.Successes {
		if len(s.ClaimTokens) != 3 {
			t.Errorf("tenant %v: got %d tokens, want 3", s.TenantID, len(s.ClaimTokens))
		}
	}
}

func TestBulkGenerateClaimTokens_PartialFailureReturnsTokensIssuedSoFar(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New()}
	tokens := newStubTokens()
	tokens.fail[tenants[0]] = 2 // succeed on calls 1 & 2, fail on call 3
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, nil, nil, tokens, nil, svctenant.BulkOptions{})
	res, err := svc.BulkGenerateClaimTokens(context.Background(), uuid.New(), uuid.New(), nil, 5, time.Hour)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(res.Failures) != 1 || len(res.Successes) != 0 {
		t.Fatalf("expected 1 failure 0 success, got %d/%d", len(res.Successes), len(res.Failures))
	}
	if len(res.Failures[0].ClaimTokens) != 2 {
		t.Fatalf("expected 2 issued-so-far tokens, got %d", len(res.Failures[0].ClaimTokens))
	}
}

// integrationCheck pins that the BulkService works against a real
// memory store + real msp.AssignTenant + stub policy applier. This
// is the lowest-level test that exercises authorizedTenants ->
// stub authz -> fanOut.
func TestBulkService_IntegratesWithRealMSPRepo(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	mspRepo := memory.NewMSPRepository(store)
	ctx := context.Background()

	t1, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	msp, _ := mspRepo.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme"})
	if _, err := mspRepo.AssignTenant(ctx, msp.ID, t1.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}

	policy := newStubPolicy()
	authz := stubAuthz{tenants: []uuid.UUID{t1.ID}}
	svc := svctenant.NewBulkService(mspRepo, authz, policy, nil, nil, nil, svctenant.BulkOptions{})
	res, err := svc.ApplyPolicyTemplateToTenants(ctx, msp.ID, uuid.New(), nil, json.RawMessage(`{"v":1}`))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(res.Successes) != 1 || res.Successes[0].TenantID != t1.ID {
		t.Fatalf("unexpected outcome: %#v", res)
	}
}
