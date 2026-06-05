package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestExpectedTenantContextRoundTrip(t *testing.T) {
	ctx := context.Background()
	if got, ok := ExpectedTenantFromContext(ctx); ok || got != "" {
		t.Fatalf("empty context: got (%q, %v), want (\"\", false)", got, ok)
	}

	const tenant = "11111111-1111-1111-1111-111111111111"
	ctx = WithExpectedTenant(ctx, tenant)
	got, ok := ExpectedTenantFromContext(ctx)
	if !ok || got != tenant {
		t.Fatalf("populated context: got (%q, %v), want (%q, true)", got, ok, tenant)
	}
}

// TestSetTenantGUC_MismatchFailsClosed verifies that when the context
// carries an authoritatively-resolved tenant (WithExpectedTenant) that
// differs from the tenant a query is about to scope to, setTenantGUC
// fails closed BEFORE issuing any SQL. Because the guard returns before
// touching the transaction, a nil pgx.Tx is sufficient — if the guard
// regresses, this test panics on the nil tx instead of silently
// passing, which is the louder failure we want.
func TestSetTenantGUC_MismatchFailsClosed(t *testing.T) {
	ctx := WithExpectedTenant(context.Background(), "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	err := setTenantGUC(ctx, nil, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "tenant context mismatch") {
		t.Fatalf("error = %q, want it to mention 'tenant context mismatch'", err)
	}
}
