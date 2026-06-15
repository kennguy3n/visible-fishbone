package complianceauto

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// The fakes below are minimal readers satisfying the adapter's narrow
// projections. They return just enough for Snapshot to succeed so the
// tests can focus on how the live RLS probe drives the tenant-isolation
// fields.

type fakeTenantReader struct{ region string }

func (f fakeTenantReader) Get(context.Context, uuid.UUID) (repository.Tenant, error) {
	return repository.Tenant{Region: f.region}, nil
}
func (f fakeTenantReader) ListTenantActivity(context.Context) ([]repository.TenantActivity, error) {
	return nil, nil
}

type fakePolicyReader struct{}

func (fakePolicyReader) GetCurrentGraph(context.Context, uuid.UUID) (repository.PolicyGraph, error) {
	return repository.PolicyGraph{}, repository.ErrNotFound
}

type fakeSigningReader struct{}

func (fakeSigningReader) GetActive(context.Context, uuid.UUID) (repository.PolicySigningKey, error) {
	return repository.PolicySigningKey{}, repository.ErrNotFound
}

type fakeIDPReader struct{}

func (fakeIDPReader) List(context.Context, uuid.UUID) ([]repository.IDPConfig, error) {
	return nil, nil
}

type fakeAuditReader struct{}

func (fakeAuditReader) List(context.Context, uuid.UUID, repository.AuditFilter, repository.Page) (repository.PageResult[repository.AuditEntry], error) {
	return repository.PageResult[repository.AuditEntry]{}, nil
}

// fakeRLSProbe is a counting rlsProbe so tests can assert both the value
// the adapter threads into the snapshot and how many times it probes.
type fakeRLSProbe struct {
	status repository.ComplianceAutoRLSStatus
	err    error
	calls  int
}

func (f *fakeRLSProbe) RLSRuntimeStatus(context.Context) (repository.ComplianceAutoRLSStatus, error) {
	f.calls++
	if f.err != nil {
		return repository.ComplianceAutoRLSStatus{}, f.err
	}
	return f.status, nil
}

func newAdapter(t *testing.T, probe rlsProbe, defaults ManagedDefaults) *PlatformAdapter {
	t.Helper()
	return NewPlatformAdapter(
		fakeTenantReader{region: "eu-west-1"},
		fakePolicyReader{},
		fakeSigningReader{},
		fakeIDPReader{},
		fakeAuditReader{},
		probe,
		defaults,
		nil,
	)
}

// TestAdapter_RLSProbeOverridesDefault proves the live probe — not the
// config-presence default — determines the isolation verdict, in both
// directions, and that the role facts are threaded into the snapshot.
func TestAdapter_RLSProbeOverridesDefault(t *testing.T) {
	t.Parallel()

	// Probe says enforced even though the config default is false.
	probe := &fakeRLSProbe{status: repository.ComplianceAutoRLSStatus{Role: "sng_app", Enforced: true}}
	a := newAdapter(t, probe, ManagedDefaults{RLSEnforced: false})
	snap, err := a.Snapshot(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !snap.RLSEnforced || !snap.RLSRuntimeVerified || snap.RLSRole != "sng_app" || snap.RLSRoleBypasses {
		t.Fatalf("enforced probe not threaded: %+v", snap)
	}

	// Probe says a BYPASSRLS role even though the config default is true.
	probe = &fakeRLSProbe{status: repository.ComplianceAutoRLSStatus{Role: "postgres", BypassRLS: true, Enforced: false}}
	a = newAdapter(t, probe, ManagedDefaults{RLSEnforced: true})
	snap, err = a.Snapshot(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.RLSEnforced || !snap.RLSRuntimeVerified || !snap.RLSRoleBypasses {
		t.Fatalf("bypassing probe not threaded: %+v", snap)
	}
}

// TestAdapter_RLSProbeCachedOnce proves a successful probe is performed
// at most once across many snapshots — the verdict is an infrastructure
// invariant, so it must not be re-read per tenant per sweep.
func TestAdapter_RLSProbeCachedOnce(t *testing.T) {
	t.Parallel()

	probe := &fakeRLSProbe{status: repository.ComplianceAutoRLSStatus{Role: "sng_app", Enforced: true}}
	a := newAdapter(t, probe, ManagedDefaults{})
	for i := 0; i < 5; i++ {
		if _, err := a.Snapshot(context.Background(), uuid.New()); err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
	}
	if probe.calls != 1 {
		t.Fatalf("probe calls = %d, want 1 (cached)", probe.calls)
	}
}

// TestAdapter_RLSProbeFallbackOnError proves a probe failure falls back to
// the config-presence default (never a false fail) and is retried on the
// next snapshot rather than caching the error.
func TestAdapter_RLSProbeFallbackOnError(t *testing.T) {
	t.Parallel()

	probe := &fakeRLSProbe{err: errors.New("db down")}
	a := newAdapter(t, probe, ManagedDefaults{RLSEnforced: true})
	snap, err := a.Snapshot(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !snap.RLSEnforced {
		t.Fatal("fallback: RLSEnforced should follow the config default on probe error")
	}
	if snap.RLSRuntimeVerified {
		t.Fatal("fallback: RLSRuntimeVerified must be false on probe error")
	}
	if _, err := a.Snapshot(context.Background(), uuid.New()); err != nil {
		t.Fatalf("snapshot 2: %v", err)
	}
	if probe.calls != 2 {
		t.Fatalf("probe calls = %d, want 2 (retried after error)", probe.calls)
	}
}

// TestAdapter_NoProbeUsesDefault proves a nil probe leaves the config
// default in place and marks the verdict as not runtime-verified.
func TestAdapter_NoProbeUsesDefault(t *testing.T) {
	t.Parallel()

	a := newAdapter(t, nil, ManagedDefaults{RLSEnforced: true})
	snap, err := a.Snapshot(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !snap.RLSEnforced || snap.RLSRuntimeVerified {
		t.Fatalf("nil probe: want enforced-by-default, not runtime-verified: %+v", snap)
	}
}
