package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultBulkConcurrency is the per-call goroutine cap for MSP bulk
// operations. Mirrors the alert-feedback worker pattern: bounded so
// a single MSP fanning out across thousands of tenants cannot
// exhaust the DB connection pool. Tunable via BulkOptions.
const DefaultBulkConcurrency = 16

// BulkOptions configures the fan-out behaviour of every BulkService
// method. The zero value is valid and applies DefaultBulkConcurrency.
type BulkOptions struct {
	// Concurrency caps the in-flight per-tenant goroutines. Values
	// <= 0 fall back to DefaultBulkConcurrency.
	Concurrency int
}

func (o BulkOptions) concurrency() int {
	if o.Concurrency <= 0 {
		return DefaultBulkConcurrency
	}
	return o.Concurrency
}

// BulkTenantOutcome is the per-tenant result inside a BulkResult.
// Exactly one of Error or one of the result payload fields is set.
type BulkTenantOutcome struct {
	TenantID uuid.UUID
	// Error is the per-tenant failure, if any.
	Error error
	// PolicyVersion is the new policy graph version on success
	// (ApplyPolicyTemplateToTenants only). Zero otherwise.
	PolicyVersion int
	// SiteID is the newly provisioned site's UUID on success
	// (BulkProvisionSites only). uuid.Nil otherwise.
	SiteID uuid.UUID
	// ClaimTokens is the set of plaintext claim tokens returned
	// for a tenant on success (BulkGenerateClaimTokens only).
	ClaimTokens []string
}

// BulkResult is the aggregate return of every bulk operation. It
// reports per-tenant outcomes (success or per-tenant error) and the
// run-level summary. Partial failures NEVER abort the run.
type BulkResult struct {
	Successes []BulkTenantOutcome
	Failures  []BulkTenantOutcome
	StartedAt time.Time
	EndedAt   time.Time
}

// Total returns the count of tenants attempted.
func (r BulkResult) Total() int { return len(r.Successes) + len(r.Failures) }

// PolicyTemplateApplier is the narrow interface BulkService needs
// from the policy service. Implemented by *policy.Service via its
// PutGraph method.
type PolicyTemplateApplier interface {
	PutGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error)
}

// SiteProvisioner is the narrow interface BulkService needs from
// the site service. Implemented by *site.Service via its Create
// method.
type SiteProvisioner interface {
	Create(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, s repository.Site) (repository.Site, error)
}

// ClaimTokenIssuer is the narrow interface BulkService needs from
// the identity service. Implemented by *identity.Service via its
// GenerateClaimToken method. The return type is the (token,
// plaintext) tuple identity returns; bulk consumers only need the
// plaintext.
type ClaimTokenIssuer interface {
	GenerateClaimToken(ctx context.Context, tenantID uuid.UUID, ttl time.Duration, createdBy *uuid.UUID) (ClaimTokenResult, error)
}

// ClaimTokenResult is the subset of identity.GenerateClaimTokenResult
// that bulk callers need. Mirrors the existing identity service
// return shape but is duplicated here to keep the bulk package
// from importing identity (which would be a cycle once the handler
// layer wires both).
type ClaimTokenResult struct {
	Plaintext string
	ExpiresAt time.Time
}

// AuthorizedTenantsLister is the narrow interface BulkService needs
// to enumerate the authorized tenant subset under an MSP. Mirrors
// the rbac.Service signature so the production wiring binds
// *rbac.Service directly. Returning a flat slice of tenant UUIDs
// keeps the dependency loose-coupled and avoids dragging the
// MSPRepository up into this package.
//
// `permission` is the bulk-op permission string (e.g.
// `msp.bulk_apply_policy`) that the caller has already gated at
// MSP scope via the handler middleware. The rbac service uses it
// to short-circuit the per-tenant grant scan only for users whose
// platform/msp-scope grants actually include that permission —
// round-6 of Devin Review caught the previous wildcard-only check
// silently denying authorized operators with a specific
// (non-wildcard) permission.
type AuthorizedTenantsLister interface {
	ListAuthorizedTenants(ctx context.Context, userID, mspID uuid.UUID, permission string, msps repository.MSPRepository) ([]uuid.UUID, error)
}

// Bulk-op permission constants used by BulkService when calling
// AuthorizedTenantsLister.ListAuthorizedTenants. Kept here
// (rather than the rbac package) because they describe MSP
// bulk-operation surfaces owned by this service; the rbac
// package treats them as opaque strings.
const (
	PermissionBulkApplyPolicy        = "msp.bulk_apply_policy"
	PermissionBulkProvisionSites     = "msp.bulk_provision_sites"
	PermissionBulkGenerateClaimToken = "msp.bulk_generate_claim_tokens" //nolint:gosec // permission name, not a credential
)

// BulkService wires the dependencies needed for MSP-fan-out
// operations. Construction is "supply whatever the call needs, nil
// the rest" so the handler layer can wire a minimal subset for
// testing.
type BulkService struct {
	msps    repository.MSPRepository
	authz   AuthorizedTenantsLister
	policy  PolicyTemplateApplier
	sites   SiteProvisioner
	tokens  ClaimTokenIssuer
	logger  *slog.Logger
	options BulkOptions
}

// NewBulkService returns a ready-to-use BulkService.
func NewBulkService(
	msps repository.MSPRepository,
	authz AuthorizedTenantsLister,
	policy PolicyTemplateApplier,
	sites SiteProvisioner,
	tokens ClaimTokenIssuer,
	logger *slog.Logger,
	options BulkOptions,
) *BulkService {
	if logger == nil {
		logger = slog.Default()
	}
	return &BulkService{
		msps: msps, authz: authz, policy: policy, sites: sites, tokens: tokens,
		logger: logger, options: options,
	}
}

// ApplyPolicyTemplateToTenants applies the given policy graph
// (as raw JSON, in the same shape policy.PutGraph accepts) to
// every authorized tenant under the MSP. Per-tenant failures are
// captured in the BulkResult; the run never aborts on a single
// tenant's failure.
//
// userID is used to compute the authorized tenant subset (an
// operator may have msp-scope read but only tenant-scope write on
// a subset). actorID is propagated to PutGraph as the audit
// actor; typically these are the same UUID for human operators.
func (svc *BulkService) ApplyPolicyTemplateToTenants(
	ctx context.Context,
	mspID, userID uuid.UUID,
	actorID *uuid.UUID,
	templateGraph json.RawMessage,
) (BulkResult, error) {
	if svc.policy == nil {
		return BulkResult{}, errors.New("bulk: policy applier not wired")
	}
	if len(templateGraph) == 0 {
		return BulkResult{}, fmt.Errorf("bulk: empty policy template: %w", repository.ErrInvalidArgument)
	}
	tenants, err := svc.authorizedTenants(ctx, mspID, userID, PermissionBulkApplyPolicy)
	if err != nil {
		return BulkResult{}, err
	}
	return svc.fanOut(ctx, tenants, func(ctx context.Context, tid uuid.UUID) BulkTenantOutcome {
		// Deep-copy templateGraph per fan-out call so each goroutine
		// owns its own json.RawMessage backing array. Without this the
		// same slice header is handed to N concurrent PutGraph calls;
		// any future in-place rewrite (e.g. canonicalisation, embedded
		// signing fields, audit annotation) would race across
		// goroutines on the shared underlying byte array. Mirrors the
		// per-tenant config clone in BulkProvisionSites below.
		graphCopy := append(json.RawMessage(nil), templateGraph...)
		graph, err := svc.policy.PutGraph(ctx, tid, actorID, graphCopy)
		if err != nil {
			return BulkTenantOutcome{TenantID: tid, Error: err}
		}
		return BulkTenantOutcome{TenantID: tid, PolicyVersion: graph.Version}
	}), nil
}

// BulkProvisionSites creates one site per authorized tenant under
// the MSP from the same site template (name + template + config).
// The template is applied verbatim per-tenant; per-tenant slug
// collisions surface as per-tenant errors and do not abort the
// run.
func (svc *BulkService) BulkProvisionSites(
	ctx context.Context,
	mspID, userID uuid.UUID,
	actorID *uuid.UUID,
	siteTemplate repository.Site,
) (BulkResult, error) {
	if svc.sites == nil {
		return BulkResult{}, errors.New("bulk: site provisioner not wired")
	}
	if siteTemplate.Name == "" {
		return BulkResult{}, fmt.Errorf("bulk: site template name required: %w", repository.ErrInvalidArgument)
	}
	tenants, err := svc.authorizedTenants(ctx, mspID, userID, PermissionBulkProvisionSites)
	if err != nil {
		return BulkResult{}, err
	}
	return svc.fanOut(ctx, tenants, func(ctx context.Context, tid uuid.UUID) BulkTenantOutcome {
		// Deep defensive copy so per-tenant mutations (e.g. the
		// site repo stamping the tenant ID, or any future
		// SiteProvisioner that canonicalises Config in-place)
		// cannot race across goroutines. The struct copy alone
		// is shallow — the json.RawMessage backing array
		// (Site.Config) would otherwise be shared and a
		// concurrent in-place write would produce a data race
		// invisible to `go vet`. Site.Template is a string-typed
		// alias (SiteTemplate), so the value-copy from `s :=
		// siteTemplate` is already safe for it.
		s := siteTemplate
		s.ID = uuid.Nil
		s.TenantID = uuid.Nil
		if len(siteTemplate.Config) > 0 {
			s.Config = append(json.RawMessage(nil), siteTemplate.Config...)
		}
		created, err := svc.sites.Create(ctx, tid, actorID, s)
		if err != nil {
			return BulkTenantOutcome{TenantID: tid, Error: err}
		}
		return BulkTenantOutcome{TenantID: tid, SiteID: created.ID}
	}), nil
}

// BulkGenerateClaimTokens issues `count` claim tokens with the
// given TTL for every authorized tenant under the MSP. The
// returned BulkResult.Successes[i].ClaimTokens holds the plaintext
// tokens — they are NOT persisted in plaintext anywhere else, so
// the caller is responsible for delivering them to operators
// promptly. Partial failures yield a per-tenant entry in Failures.
func (svc *BulkService) BulkGenerateClaimTokens(
	ctx context.Context,
	mspID, userID uuid.UUID,
	actorID *uuid.UUID,
	count int,
	ttl time.Duration,
) (BulkResult, error) {
	if svc.tokens == nil {
		return BulkResult{}, errors.New("bulk: claim token issuer not wired")
	}
	if count <= 0 {
		return BulkResult{}, fmt.Errorf("bulk: count must be > 0: %w", repository.ErrInvalidArgument)
	}
	tenants, err := svc.authorizedTenants(ctx, mspID, userID, PermissionBulkGenerateClaimToken)
	if err != nil {
		return BulkResult{}, err
	}
	return svc.fanOut(ctx, tenants, func(ctx context.Context, tid uuid.UUID) BulkTenantOutcome {
		// Issue tokens concurrently within the tenant, bounded
		// by perTenantTokenConcurrency. Round-17 of Devin
		// Review on PR #42 (ANALYSIS_0002) flagged that the
		// previous sequential loop made per-tenant wall-clock
		// dominate at high counts (e.g. count=1000 × ~10ms per
		// DB insert = ~10s per tenant). Pushing the parallelism
		// into the inner loop scales the per-tenant latency
		// down by the inner cap, while the outer fanOut limit
		// still bounds the total goroutine count to
		// (outer × inner). Each goroutine writes into its own
		// `plaintexts[i]` slot so there's no shared mutation.
		//
		// Round-25 of Devin Review on PR #42 (ANALYSIS_0002)
		// flagged a subtle correctness issue with the previous
		// `errgroup.WithContext` shape: when goroutine A's
		// GenerateClaimToken failed, the derived ctx was
		// cancelled, and goroutine B (whose token may have
		// already been persisted server-side) could have its
		// next pool operation aborted with `context.Canceled`
		// before the function returned — so the plaintext was
		// never written to the slot and the operator lost a
		// persisted-but-unreported token. The token is
		// recoverable via the identity service's admin path,
		// but the API contract claimed "plaintexts are NEVER
		// persisted elsewhere" so this was a real leak.
		//
		// The fix: plain `errgroup.Group` (no derived ctx).
		// A failing call no longer cancels siblings; every
		// goroutine sees the parent ctx directly. Wall-clock
		// cost in the failure path increases marginally (we
		// wait for the remaining count-1 calls to complete
		// instead of short-circuiting), but token issuance is
		// rare, count is small, and the correctness gain
		// dominates. SetLimit still bounds the in-flight
		// goroutines so a high count doesn't fan out beyond
		// perTenantTokenConcurrency.
		const perTenantTokenConcurrency = 8
		plaintexts := make([]string, count)
		var ig errgroup.Group
		limit := perTenantTokenConcurrency
		if limit > count {
			limit = count
		}
		ig.SetLimit(limit)
		for i := 0; i < count; i++ {
			i := i
			ig.Go(func() error {
				r, err := svc.tokens.GenerateClaimToken(ctx, tid, ttl, actorID)
				if err != nil {
					return err
				}
				plaintexts[i] = r.Plaintext
				return nil
			})
		}
		firstErr := ig.Wait()
		issued := make([]string, 0, count)
		for _, p := range plaintexts {
			if p != "" {
				issued = append(issued, p)
			}
		}
		if firstErr != nil {
			// Best-effort: surface the first failure with
			// whatever tokens were generated so the caller
			// can decide whether to deliver the partial
			// batch or roll back externally.
			return BulkTenantOutcome{
				TenantID:    tid,
				Error:       fmt.Errorf("issued %d of %d before failure: %w", len(issued), count, firstErr),
				ClaimTokens: issued,
			}
		}
		return BulkTenantOutcome{TenantID: tid, ClaimTokens: issued}
	}), nil
}

// authorizedTenants resolves the per-user authorized tenant subset
// for `mspID` and the specific bulk-op `permission`. Returns an
// error if no AuthorizedTenantsLister was wired (programmer
// error). The permission string flows through to the rbac
// service's broad-authority check so platform/msp-scope grants
// with that specific permission broaden the tenant set; see the
// AuthorizedTenantsLister doc-comment for the rationale.
func (svc *BulkService) authorizedTenants(ctx context.Context, mspID, userID uuid.UUID, permission string) ([]uuid.UUID, error) {
	if svc.authz == nil {
		return nil, errors.New("bulk: authorized tenants lister not wired")
	}
	tenants, err := svc.authz.ListAuthorizedTenants(ctx, userID, mspID, permission, svc.msps)
	if err != nil {
		return nil, fmt.Errorf("bulk: list authorized tenants: %w", err)
	}
	// Defensive copy: ListAuthorizedTenants may return a slice
	// backed by an internal repository array. Sorting in place
	// would mutate caller-owned data — a particularly subtle
	// foot-gun in tests where the caller holds the same slice
	// for assertions.
	out := make([]uuid.UUID, len(tenants))
	copy(out, tenants)
	// Sort by UUID byte order so audit logs observe a
	// deterministic iteration order independent of underlying
	// map iteration.
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out, nil
}

// fanOut runs work(ctx, tenantID) for every tenant in `tenants`
// inside an errgroup bounded by the configured concurrency limit.
// Partial failures are captured as per-tenant outcomes; the run
// never aborts on a single tenant's failure (errgroup is only used
// for its SetLimit semaphore, never to propagate errors — work
// always returns nil).
//
// Implementation note: a plain errgroup.Group is used here rather
// than errgroup.WithContext because work always returns nil, so
// the WithContext cancellation channel would be unreachable from
// inside this scope. Parent-context cancellation still propagates
// — `ctx` is the parent context passed through unchanged, and the
// per-tenant work closure observes it directly. Round-23 of Devin
// Review on PR #42 (ANALYSIS_0001) flagged the unused cancellation
// channel as a clarity nit.
func (svc *BulkService) fanOut(
	ctx context.Context,
	tenants []uuid.UUID,
	work func(context.Context, uuid.UUID) BulkTenantOutcome,
) BulkResult {
	startedAt := time.Now().UTC()
	results := make([]BulkTenantOutcome, len(tenants))
	var g errgroup.Group
	g.SetLimit(svc.options.concurrency())
	for i, tid := range tenants {
		i, tid := i, tid
		g.Go(func() error {
			results[i] = work(ctx, tid)
			return nil
		})
	}
	_ = g.Wait()

	out := BulkResult{StartedAt: startedAt, EndedAt: time.Now().UTC()}
	for _, r := range results {
		if r.Error != nil {
			out.Failures = append(out.Failures, r)
		} else {
			out.Successes = append(out.Successes, r)
		}
	}
	return out
}
