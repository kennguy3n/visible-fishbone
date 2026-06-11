package appdb_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// EnsureProtection must tighten an under-protected app, be idempotent
// on repeat, never loosen a stricter current class, and validate input.

func TestEnsureProtection_TightensAndIsIdempotent(t *testing.T) {
	svc, tenantID := newTestService(t)
	ctx := context.Background()
	// App is trusted_direct (rank 0) in the global catalog.
	seedApp(t, svc, "Drive", repository.TrafficClassTrustedDirect, "*.drive.example.com")

	created, err := svc.EnsureProtection(ctx, tenantID, nil, "files.drive.example.com",
		[]string{"*.drive.example.com"}, repository.TrafficClassInspectFull, "noops auto-protect")
	if err != nil {
		t.Fatalf("EnsureProtection: %v", err)
	}
	if !created {
		t.Fatalf("created = false, want true (trusted_direct -> inspect_full tightens)")
	}
	cls, err := svc.ResolveTrafficClass(ctx, tenantID, "files.drive.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassInspectFull {
		t.Fatalf("effective class = %q, want inspect_full", cls)
	}

	// Second call is a no-op: already at inspect_full.
	created2, err := svc.EnsureProtection(ctx, tenantID, nil, "files.drive.example.com",
		[]string{"*.drive.example.com"}, repository.TrafficClassInspectFull, "noops auto-protect")
	if err != nil {
		t.Fatalf("EnsureProtection (repeat): %v", err)
	}
	if created2 {
		t.Fatalf("created = true on repeat, want false (idempotent)")
	}
}

func TestEnsureProtection_NeverLoosens(t *testing.T) {
	svc, tenantID := newTestService(t)
	ctx := context.Background()
	// App is already blocked (rank 4) — the strictest class.
	seedApp(t, svc, "Bad", repository.TrafficClassBlock, "*.bad.example.com")

	created, err := svc.EnsureProtection(ctx, tenantID, nil, "login.bad.example.com",
		[]string{"*.bad.example.com"}, repository.TrafficClassInspectFull, "noops auto-protect")
	if err != nil {
		t.Fatalf("EnsureProtection: %v", err)
	}
	if created {
		t.Fatalf("created = true, want false (must not loosen block -> inspect_full)")
	}
	cls, err := svc.ResolveTrafficClass(ctx, tenantID, "login.bad.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cls != repository.TrafficClassBlock {
		t.Fatalf("effective class = %q, want block (unchanged)", cls)
	}
}

func TestEnsureProtection_Validation(t *testing.T) {
	svc, tenantID := newTestService(t)
	ctx := context.Background()
	cases := []struct {
		name    string
		probe   string
		domains []string
		target  repository.TrafficClass
	}{
		{"empty probe", "", []string{"*.x.example.com"}, repository.TrafficClassInspectFull},
		{"no domains", "x.example.com", nil, repository.TrafficClassInspectFull},
		{"invalid target", "x.example.com", []string{"*.x.example.com"}, repository.TrafficClass("bogus")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.EnsureProtection(ctx, tenantID, nil, tc.probe, tc.domains, tc.target, "r")
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}
