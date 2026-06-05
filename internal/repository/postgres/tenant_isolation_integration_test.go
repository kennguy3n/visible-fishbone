//go:build integration

package postgres_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

// TestCrossTenantIsolation_Sweep is the defense-in-depth assertion
// that RLS (the primary boundary) actually denies cross-tenant reads
// across a representative sweep of tenant-scoped repository
// interfaces. For each repository it seeds a row under tenant A and
// then, using tenant B's id, asserts:
//
//   - List returns ZERO rows (RLS filters the row out), and
//   - Get(idFromA) returns ErrNotFound (the row is invisible, not
//     just unreadable).
//
// Every repository routes tenant-scoped queries through the same
// Store.withTenant / withTenantRO path (which sets and re-asserts the
// sng.tenant_id GUC), so a single regression in that path would break
// EVERY case here at once — making this sweep a high-signal guard for
// the whole tenant-isolation mechanism rather than any one table.
func TestCrossTenantIsolation_Sweep(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	tr := store.NewTenantRepository()
	tntA := mustTenant(t, tr)
	tntB := mustTenant(t, tr)

	rnd := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand: %v", err)
		}
		return b
	}

	// Each case seeds one row under tenant A and reports its id, then
	// asserts tenant B sees nothing through both List and Get.
	cases := []struct {
		name string
		// seed creates a row under tenantA and returns its id.
		seed func(tenantA uuid.UUID) (uuid.UUID, error)
		// listEmpty returns true if tenantB's List is empty.
		listEmpty func(tenantB uuid.UUID) (bool, error)
		// getNotFound returns the error of tenantB.Get(idFromA).
		getNotFound func(tenantB, idFromA uuid.UUID) error
	}{
		{
			name: "Device",
			seed: func(a uuid.UUID) (uuid.UUID, error) {
				dr := store.NewDeviceRepository()
				d, err := dr.Create(bgCtx(), a, repository.Device{
					Name: "dev-A", Platform: repository.DevicePlatformIOS,
					Status: repository.DeviceStatusActive,
				})
				return d.ID, err
			},
			listEmpty: func(b uuid.UUID) (bool, error) {
				res, err := store.NewDeviceRepository().List(bgCtx(), b, repository.DeviceListFilter{}, repository.Page{Limit: 100})
				return len(res.Items) == 0, err
			},
			getNotFound: func(b, id uuid.UUID) error {
				_, err := store.NewDeviceRepository().Get(bgCtx(), b, id)
				return err
			},
		},
		{
			name: "WebhookEndpoint",
			seed: func(a uuid.UUID) (uuid.UUID, error) {
				ep, err := store.NewWebhookEndpointRepository().Create(bgCtx(), a, repository.WebhookEndpoint{
					URL: "https://a.example/hook", Events: []string{"tenant.created"},
					SigningSecret: rnd(32), Status: repository.WebhookEndpointStatusActive,
				})
				return ep.ID, err
			},
			listEmpty: func(b uuid.UUID) (bool, error) {
				res, err := store.NewWebhookEndpointRepository().List(bgCtx(), b, repository.Page{Limit: 100})
				return len(res.Items) == 0, err
			},
			getNotFound: func(b, id uuid.UUID) error {
				_, err := store.NewWebhookEndpointRepository().Get(bgCtx(), b, id)
				return err
			},
		},
		{
			name: "TenantAPIKey",
			seed: func(a uuid.UUID) (uuid.UUID, error) {
				k, err := store.NewTenantAPIKeyRepository().Create(bgCtx(), a, repository.TenantAPIKey{
					Name: "ci-bot", Subject: "bot:a", Hash: rnd(32),
					Status: repository.TenantAPIKeyStatusActive,
				})
				return k.ID, err
			},
			listEmpty: func(b uuid.UUID) (bool, error) {
				ks, err := store.NewTenantAPIKeyRepository().List(bgCtx(), b)
				return len(ks) == 0, err
			},
			getNotFound: func(b, id uuid.UUID) error {
				_, err := store.NewTenantAPIKeyRepository().Get(bgCtx(), b, id)
				return err
			},
		},
		{
			name: "PolicySigningKey",
			seed: func(a uuid.UUID) (uuid.UUID, error) {
				k, err := store.NewPolicySigningKeyRepository().Create(bgCtx(), a, repository.PolicySigningKey{
					KeyID: "ka-1", Algorithm: "ed25519",
					PublicKey: rnd(32), PrivateKey: rnd(32),
					Status: repository.PolicySigningKeyStatusActive,
				})
				return k.ID, err
			},
			listEmpty: func(b uuid.UUID) (bool, error) {
				ks, err := store.NewPolicySigningKeyRepository().List(bgCtx(), b)
				return len(ks) == 0, err
			},
			getNotFound: func(b, _ uuid.UUID) error {
				// PolicySigningKey is addressed by its stable KeyID, not
				// a row UUID; cross-tenant lookup of A's KeyID under B
				// must be ErrNotFound.
				_, err := store.NewPolicySigningKeyRepository().GetByKeyID(bgCtx(), b, "ka-1")
				return err
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			idFromA, err := tc.seed(tntA.ID)
			if err != nil {
				t.Fatalf("seed under tenant A: %v", err)
			}

			// Sanity: tenant A CAN see its own row (otherwise an empty
			// List below would be meaningless).
			if empty, err := tc.listEmpty(tntA.ID); err != nil {
				t.Fatalf("list under tenant A: %v", err)
			} else if empty {
				t.Fatalf("precondition failed: tenant A cannot see its own %s row", tc.name)
			}

			// Cross-tenant List must be empty.
			if empty, err := tc.listEmpty(tntB.ID); err != nil {
				t.Fatalf("list under tenant B: %v", err)
			} else if !empty {
				t.Errorf("%s: tenant B List returned rows belonging to tenant A", tc.name)
			}

			// Cross-tenant Get must be ErrNotFound (invisible, not just
			// unreadable).
			if err := tc.getNotFound(tntB.ID, idFromA); !errors.Is(err, repository.ErrNotFound) {
				t.Errorf("%s: cross-tenant Get err = %v, want ErrNotFound", tc.name, err)
			}
		})
	}
}

// TestExpectedTenantGuard_FailsClosed exercises the request-edge →
// data-layer assertion end-to-end: when the context carries an
// authoritatively-resolved tenant (postgres.WithExpectedTenant, stamped
// by the auth/tenant middleware) that diverges from the tenant a
// repository call is scoped to, the query must fail closed BEFORE
// touching any row — catching a handler that authorized one tenant but
// issued a repository call for another. The matching-tenant case must
// continue to succeed so the guard does not block legitimate traffic.
func TestExpectedTenantGuard_FailsClosed(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	tr := store.NewTenantRepository()
	tntA := mustTenant(t, tr)
	tntB := mustTenant(t, tr)
	dr := store.NewDeviceRepository()

	// Divergent: context resolved to tenant B, query scoped to tenant A.
	mismatchCtx := postgres.WithExpectedTenant(bgCtx(), tntB.ID.String())
	if _, err := dr.List(mismatchCtx, tntA.ID, repository.DeviceListFilter{}, repository.Page{Limit: 1}); err == nil {
		t.Error("expected mismatch error when resolved tenant != query tenant, got nil")
	}

	// Aligned: context resolved to tenant A, query scoped to tenant A.
	matchCtx := postgres.WithExpectedTenant(bgCtx(), tntA.ID.String())
	if _, err := dr.List(matchCtx, tntA.ID, repository.DeviceListFilter{}, repository.Page{Limit: 1}); err != nil {
		t.Errorf("aligned resolved/query tenant should succeed, got %v", err)
	}
}
