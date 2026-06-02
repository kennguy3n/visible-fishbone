package tenant_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

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

func (s stubAuthz) ListAuthorizedTenants(_ context.Context, _, _ uuid.UUID, _ string, _ repository.MSPRepository) ([]uuid.UUID, error) {
	return s.tenants, s.err
}

// stubPolicy implements PolicyTemplateApplier.
type stubPolicy struct {
	inflight atomic.Int64
	maxLive  atomic.Int64

	mu      sync.Mutex
	fail    map[uuid.UUID]error
	got     map[uuid.UUID]json.RawMessage
	rawPtrs map[uuid.UUID]uintptr // backing-array address of the `raw` arg seen by PutGraph
}

func newStubPolicy() *stubPolicy {
	return &stubPolicy{
		fail:    map[uuid.UUID]error{},
		got:     map[uuid.UUID]json.RawMessage{},
		rawPtrs: map[uuid.UUID]uintptr{},
	}
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
	// Snapshot the backing-array address BEFORE any internal copy
	// so the deep-copy invariant can be asserted by callers without
	// the stub itself accidentally hiding aliasing.
	var rawPtr uintptr
	if len(raw) > 0 {
		rawPtr = uintptr(unsafe.Pointer(&raw[0]))
	}
	time.Sleep(2 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, ok := s.fail[tid]; ok {
		return repository.PolicyGraph{}, err
	}
	s.got[tid] = append(json.RawMessage{}, raw...)
	s.rawPtrs[tid] = rawPtr
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

// stubTokens implements ClaimTokenIssuer. `delay` simulates DB
// latency so per-tenant parallelism is observable via the
// `maxInFlight` and `inFlight` atomic counters used by
// TestBulkGenerateClaimTokens_PerTenantInnerParallelism.
type stubTokens struct {
	mu          sync.Mutex
	fail        map[uuid.UUID]int // tenantID -> fail-after-Nth call
	calls       map[uuid.UUID]int
	plaintexts  map[uuid.UUID][]string
	delay       time.Duration
	inFlight    int64
	maxInFlight int64
}

func newStubTokens() *stubTokens {
	return &stubTokens{
		fail:       map[uuid.UUID]int{},
		calls:      map[uuid.UUID]int{},
		plaintexts: map[uuid.UUID][]string{},
	}
}

func (s *stubTokens) GenerateClaimToken(_ context.Context, tid uuid.UUID, _ time.Duration, _ *uuid.UUID) (svctenant.ClaimTokenResult, error) {
	// In-flight tracking lives outside the mutex so concurrent
	// callers actually overlap (otherwise the mutex would
	// serialise everything and maxInFlight would never exceed 1).
	in := atomic.AddInt64(&s.inFlight, 1)
	for {
		prev := atomic.LoadInt64(&s.maxInFlight)
		if in <= prev || atomic.CompareAndSwapInt64(&s.maxInFlight, prev, in) {
			break
		}
	}
	defer atomic.AddInt64(&s.inFlight, -1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
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

// TestBulkGenerateClaimTokens_PerTenantInnerParallelism pins
// round-17 of Devin Review on PR #42 (ANALYSIS_0002): the
// per-tenant token issuance must be parallelised so a single
// large-count request (e.g. count=1000) does not dominate
// per-tenant wall-clock under sequential issuance. The
// implementation caps inner parallelism at 8 and we verify that
// the in-flight concurrency observed by the stub crosses 1 (i.e.
// at least two issuer goroutines were active simultaneously). We
// also verify all 12 plaintexts are returned uniquely, ruling out
// any race that collapses or duplicates the output slice. The 50ms
// per-call delay makes the parallelism observable without
// extending test runtime materially. Errgroup-launched goroutines
// share `igctx`, so a context cancellation from a sibling tenant's
// failure would cascade — out of scope for this test.
func TestBulkGenerateClaimTokens_PerTenantInnerParallelism(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New()}
	tokens := newStubTokens()
	tokens.delay = 50 * time.Millisecond
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, nil, nil, tokens, nil, svctenant.BulkOptions{})
	res, err := svc.BulkGenerateClaimTokens(context.Background(), uuid.New(), uuid.New(), nil, 12, time.Hour)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(res.Successes) != 1 {
		t.Fatalf("expected 1 success, got %d (failures=%d)", len(res.Successes), len(res.Failures))
	}
	if len(res.Successes[0].ClaimTokens) != 12 {
		t.Fatalf("expected 12 tokens, got %d", len(res.Successes[0].ClaimTokens))
	}
	// All-unique check rules out any race that collapses output slots.
	seen := map[string]bool{}
	for _, pt := range res.Successes[0].ClaimTokens {
		if seen[pt] {
			t.Fatalf("duplicate token %q in output", pt)
		}
		seen[pt] = true
	}
	// Concurrency observed by the stub must have crossed 1.
	if maxObs := atomic.LoadInt64(&tokens.maxInFlight); maxObs < 2 {
		t.Fatalf("maxInFlight = %d; want >=2 (round-17 parallelism not active)", maxObs)
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

// TestBulkProvisionSites_ConfigBytesAreDeepCopied pins the round-4
// defensiveness fix: BulkProvisionSites must allocate a fresh
// json.RawMessage backing array for each per-tenant defensive copy.
// The previous shallow `s := siteTemplate` only copied the slice
// header; all per-tenant goroutines saw the same underlying byte
// array, which would race the instant a future SiteProvisioner
// canonicalised Config in-place. We assert the per-tenant Config
// slices have distinct backing-array addresses to pin the
// deep-copy invariant.
func TestBulkProvisionSites_ConfigBytesAreDeepCopied(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	sites := newStubSites()
	tmpl := repository.Site{
		Name:     "HQ",
		Template: repository.SiteTemplateBranch,
		Config:   json.RawMessage(`{"posture":"strict"}`),
	}
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, nil, sites, nil, nil, svctenant.BulkOptions{})
	if _, err := svc.BulkProvisionSites(context.Background(), uuid.New(), uuid.New(), nil, tmpl); err != nil {
		t.Fatalf("provision: %v", err)
	}
	sites.mu.Lock()
	defer sites.mu.Unlock()
	if len(sites.got) != len(tenants) {
		t.Fatalf("got = %d sites, want %d", len(sites.got), len(tenants))
	}

	// Each captured Config byte slice must:
	//   (a) carry the same VALUE as the template (deep copy
	//       preserves contents); and
	//   (b) NOT alias the template's backing array (deep copy
	//       allocates fresh memory).
	tmplPtr := uintptr(0)
	if len(tmpl.Config) > 0 {
		tmplPtr = uintptr(unsafe.Pointer(&tmpl.Config[0]))
	}
	seen := map[uintptr]struct{}{}
	for tid, got := range sites.got {
		if string(got.Config) != string(tmpl.Config) {
			t.Errorf("tenant %v: Config = %q, want %q", tid, got.Config, tmpl.Config)
		}
		if len(got.Config) == 0 {
			continue
		}
		p := uintptr(unsafe.Pointer(&got.Config[0]))
		if p == tmplPtr {
			t.Errorf("tenant %v: Config backing array aliases the template's (round-4 deep-copy regression)", tid)
		}
		if _, dup := seen[p]; dup {
			t.Errorf("tenant %v: Config backing array aliases another tenant's (round-4 deep-copy regression)", tid)
		}
		seen[p] = struct{}{}
	}
}

// TestApplyPolicyTemplate_TemplateGraphIsDeepCopiedPerTenant mirrors
// the round-4 BulkProvisionSites deep-copy invariant for the
// policy fan-out path: ApplyPolicyTemplateToTenants must allocate
// a fresh json.RawMessage backing array per tenant goroutine
// before invoking PutGraph. Without the copy, every per-tenant
// goroutine receives a slice header pointing at the same
// underlying byte array, which would race the instant a future
// PolicyTemplateApplier canonicalised, signed, or annotated the
// payload in place. We assert (a) every captured raw pointer is
// distinct from the input pointer, and (b) no two tenants share a
// raw pointer.
func TestApplyPolicyTemplate_TemplateGraphIsDeepCopiedPerTenant(t *testing.T) {
	t.Parallel()
	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	policy := newStubPolicy()
	tmpl := json.RawMessage(`{"version":1,"rules":[]}`)
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, policy, nil, nil, nil, svctenant.BulkOptions{})
	if _, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, tmpl); err != nil {
		t.Fatalf("apply: %v", err)
	}
	policy.mu.Lock()
	defer policy.mu.Unlock()
	if len(policy.rawPtrs) != len(tenants) {
		t.Fatalf("got = %d invocations, want %d", len(policy.rawPtrs), len(tenants))
	}
	tmplPtr := uintptr(unsafe.Pointer(&tmpl[0]))
	seen := map[uintptr]struct{}{}
	for tid, p := range policy.rawPtrs {
		if p == 0 {
			t.Errorf("tenant %v: zero rawPtr (template was empty?)", tid)
			continue
		}
		if p == tmplPtr {
			t.Errorf("tenant %v: PutGraph received the caller's templateGraph backing array (deep-copy missing)", tid)
		}
		if _, dup := seen[p]; dup {
			t.Errorf("tenant %v: PutGraph received a backing array already passed to another tenant (deep-copy missing)", tid)
		}
		seen[p] = struct{}{}
	}
}

// TestApplyPolicyTemplate_PerTenantWorkSeesParentContext pins the
// round-23 ANALYSIS_0001 fix on PR #42. The previous shape built
// the per-tenant work context via `errgroup.WithContext(ctx)`, but
// every work closure always returned nil, so the WithContext
// cancellation channel was unreachable from inside the fan-out
// scope. The fix replaced the WithContext-derived ctx with a
// plain `errgroup.Group` and threads the parent ctx through
// directly. This test verifies the resulting invariants:
//
//  1. A successful tenant's work closure does NOT cause subsequent
//     tenants' work closures to receive a cancelled context. (This
//     was already true under the old shape — work always returned
//     nil — but the test pins it so any future regression that
//     reintroduces WithContext + an `if err != nil { return err }`
//     style cancellation is caught.)
//
//  2. Parent-context cancellation DOES propagate to in-flight
//     per-tenant work. This is the contract that justifies threading
//     `ctx` directly to work rather than synthesising a fresh one.
func TestApplyPolicyTemplate_PerTenantWorkSeesParentContext(t *testing.T) {
	t.Parallel()

	// Scenario 1: successful tenant does NOT cancel siblings.
	t.Run("SuccessfulTenantDoesNotCancelSiblings", func(t *testing.T) {
		t.Parallel()
		tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
		ctxStillLive := atomic.Int64{}
		policy := newStubPolicy()
		// Patch the stub by wrapping it in an inline implementation that
		// records whether each tenant's ctx was cancelled at the moment
		// it was invoked. We use a per-test wrapper instead of mutating
		// stubPolicy so other tests aren't affected.
		wrap := contextProbingApplier{
			inner:       policy,
			liveCounter: &ctxStillLive,
		}
		svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, &wrap, nil, nil, nil, svctenant.BulkOptions{Concurrency: 4})
		res, err := svc.ApplyPolicyTemplateToTenants(context.Background(), uuid.New(), uuid.New(), nil, json.RawMessage(`{"v":1}`))
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if res.Total() != 3 || len(res.Failures) != 0 {
			t.Fatalf("expected all 3 to succeed: total=%d failures=%d", res.Total(), len(res.Failures))
		}
		if got := ctxStillLive.Load(); got != 3 {
			t.Fatalf("expected ctx live count = 3 (no cancellation from sibling success), got %d", got)
		}
	})

	// Scenario 2: parent ctx cancellation reaches in-flight work.
	t.Run("ParentCancellationPropagatesToWork", func(t *testing.T) {
		t.Parallel()
		tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
		blockedSaw := make(chan struct{}, len(tenants))
		probe := blockingApplier{blockedSaw: blockedSaw}
		svc := svctenant.NewBulkService(nil, stubAuthz{tenants: tenants}, &probe, nil, nil, nil, svctenant.BulkOptions{Concurrency: 4})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan svctenant.BulkResult, 1)
		go func() {
			res, _ := svc.ApplyPolicyTemplateToTenants(ctx, uuid.New(), uuid.New(), nil, json.RawMessage(`{}`))
			done <- res
		}()
		// Wait for all 4 tenants to be in-flight (each closure blocks
		// on the probe's ctx.Done()). Bounded wait so a stuck test
		// fails loudly.
		deadline := time.After(2 * time.Second)
		for i := 0; i < len(tenants); i++ {
			select {
			case <-blockedSaw:
			case <-deadline:
				t.Fatalf("only %d of %d tenants reached the blocking probe", i, len(tenants))
			}
		}
		cancel()
		select {
		case res := <-done:
			// Every tenant should have surfaced context.Canceled as its
			// per-tenant error.
			if len(res.Failures) != len(tenants) {
				t.Fatalf("parent cancel: want %d failures, got %d (successes=%d)",
					len(tenants), len(res.Failures), len(res.Successes))
			}
			for _, f := range res.Failures {
				if !errors.Is(f.Error, context.Canceled) {
					t.Errorf("tenant %v: want context.Canceled, got %v", f.TenantID, f.Error)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ApplyPolicyTemplateToTenants did not return after parent ctx cancel")
		}
	})
}

// contextProbingApplier wraps a PolicyTemplateApplier and increments
// liveCounter if the ctx passed to PutGraph is still live (i.e.
// `ctx.Err() == nil`) at the moment the call is observed. Used by
// the round-23 ANALYSIS_0001 regression test to verify that a
// successful sibling tenant does not cancel the per-tenant work ctx.
type contextProbingApplier struct {
	inner       svctenant.PolicyTemplateApplier
	liveCounter *atomic.Int64
}

func (p *contextProbingApplier) PutGraph(ctx context.Context, tid uuid.UUID, actor *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	if ctx.Err() == nil {
		p.liveCounter.Add(1)
	}
	return p.inner.PutGraph(ctx, tid, actor, raw)
}

// blockingApplier blocks PutGraph on ctx.Done() so callers can
// hold every tenant's work in-flight while the parent ctx is
// cancelled externally. Used by the parent-cancellation arm of
// TestApplyPolicyTemplate_PerTenantWorkSeesParentContext.
type blockingApplier struct {
	blockedSaw chan<- struct{}
}

func (p *blockingApplier) PutGraph(ctx context.Context, tid uuid.UUID, _ *uuid.UUID, _ json.RawMessage) (repository.PolicyGraph, error) {
	p.blockedSaw <- struct{}{}
	<-ctx.Done()
	return repository.PolicyGraph{}, ctx.Err()
}

// ctxAwareTokens simulates an issuer that PERSISTS the token in
// its DB before observing ctx cancellation. This is the failure
// mode the round-25 ANALYSIS_0002 fix targets: under
// errgroup.WithContext, one goroutine's failure cancels the
// derived ctx, and sibling goroutines whose tokens already landed
// server-side then see ctx.Canceled before they could write to
// their slot in the result array — losing a persisted-but-
// unreported token. With the round-25 fix (plain errgroup.Group),
// siblings see the parent ctx, never cancelled by sibling
// failures, and every persisted token reaches the response slice.
type ctxAwareTokens struct {
	mu           sync.Mutex
	failOnCall   map[uuid.UUID]int // tenantID -> 1-based call index that fails
	persisted    map[uuid.UUID]int // tenantID -> server-side token count
	calls        map[uuid.UUID]int // tenantID -> total call count
	persistDelay time.Duration
}

func (s *ctxAwareTokens) GenerateClaimToken(ctx context.Context, tid uuid.UUID, _ time.Duration, _ *uuid.UUID) (svctenant.ClaimTokenResult, error) {
	s.mu.Lock()
	s.calls[tid]++
	callIdx := s.calls[tid]
	s.mu.Unlock()
	if want, ok := s.failOnCall[tid]; ok && want == callIdx {
		return svctenant.ClaimTokenResult{}, errors.New("forced fail")
	}
	// Simulate DB persistence happening BEFORE the ctx
	// observation. After this point the token is on disk and
	// the operator has lost the plaintext if we abort.
	s.mu.Lock()
	s.persisted[tid]++
	pt := uuid.NewString()
	s.mu.Unlock()
	if s.persistDelay > 0 {
		time.Sleep(s.persistDelay)
	}
	// Now check whether ctx was cancelled out from under us by
	// a sibling failure. Pre-fix (errgroup.WithContext shape),
	// this returns ctx.Err() — the slot is never populated and
	// the persisted token leaks. Post-fix (plain Group sharing
	// parent ctx), this only returns non-nil if the CALLER's
	// parent context was cancelled — sibling failures do not
	// cascade here.
	if err := ctx.Err(); err != nil {
		return svctenant.ClaimTokenResult{}, err
	}
	return svctenant.ClaimTokenResult{Plaintext: pt, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// TestBulkGenerateClaimTokens_SiblingFailureDoesNotLosePersistedTokens
// pins round-25 of Devin Review on PR #42 (ANALYSIS_0002). With
// count=4, the first call fails immediately while three siblings
// are mid-persistence. Under the pre-fix errgroup.WithContext
// shape, the derived ctx was cancelled by the first failure and
// the three siblings — having already persisted server-side —
// would return ctx.Canceled before writing their plaintext slot.
// The operator lost three plaintexts that the API contract
// promised they would never need to recover via admin tooling.
//
// Post-fix invariant: every persisted token reaches the response
// outcome (ClaimTokens slice on the Failures entry, since the
// tenant overall failed). Concretely:
//
//	persisted == 3  &&  len(outcome.ClaimTokens) == 3
//
// If a future refactor reintroduces errgroup.WithContext-shaped
// cancellation here, persisted will be 3 but len(ClaimTokens) will
// be 0 — the test fails loudly with that exact accounting message.
func TestBulkGenerateClaimTokens_SiblingFailureDoesNotLosePersistedTokens(t *testing.T) {
	t.Parallel()
	tn := uuid.New()
	tokens := &ctxAwareTokens{
		failOnCall:   map[uuid.UUID]int{tn: 1},
		persisted:    map[uuid.UUID]int{},
		calls:        map[uuid.UUID]int{},
		persistDelay: 75 * time.Millisecond,
	}
	svc := svctenant.NewBulkService(nil, stubAuthz{tenants: []uuid.UUID{tn}}, nil, nil, tokens, nil, svctenant.BulkOptions{})
	res, err := svc.BulkGenerateClaimTokens(context.Background(), uuid.New(), uuid.New(), nil, 4, time.Hour)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// One tenant, one forced failure → tenant lands in Failures.
	if len(res.Failures) != 1 || len(res.Successes) != 0 {
		t.Fatalf("expected 1 failure / 0 success, got %d/%d", len(res.Successes), len(res.Failures))
	}
	tokens.mu.Lock()
	persisted := tokens.persisted[tn]
	tokens.mu.Unlock()
	// 3 of the 4 calls persisted server-side (the 1 forced-fail
	// returned without persisting).
	if persisted != 3 {
		t.Fatalf("test fixture: expected 3 server-side persisted tokens, got %d", persisted)
	}
	// The round-25 invariant: every persisted token must appear
	// in the outcome's ClaimTokens slice. Pre-fix would yield 0
	// here (sibling ctx cancelled before slot population).
	got := len(res.Failures[0].ClaimTokens)
	if got != persisted {
		t.Fatalf("round-25 regression: %d tokens persisted server-side but only %d returned to caller; sibling ctx-cancellation lost plaintexts", persisted, got)
	}
	// Sanity: every returned plaintext must be non-empty (no
	// empty slot leaked through).
	for i, pt := range res.Failures[0].ClaimTokens {
		if pt == "" {
			t.Fatalf("plaintext slot %d is empty in returned ClaimTokens — slot-population regression", i)
		}
	}
}
