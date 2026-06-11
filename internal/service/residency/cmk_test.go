package residency_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/residency"
)

// capturingHandler is a slog.Handler that records every emitted record
// so a test can assert on the structured audit trail.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.records = append(h.records, r.Clone())
	h.mu.Unlock()
	return nil
}
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// attrsByMessage returns the attribute key→string map of the first
// captured record with the given message, and whether it was found.
func (h *capturingHandler) attrsByMessage(msg string) (map[string]string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Message != msg {
			continue
		}
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		return attrs, true
	}
	return nil, false
}

// regionFn adapts a fixed designated region to a RegionResolver.
func regionFn(r residency.Region) residency.RegionResolver {
	return residency.RegionResolverFunc(func(context.Context, uuid.UUID) (residency.Region, error) {
		return r, nil
	})
}

// refFn adapts a fixed CMK ref to a CMKResolver.
func refFn(ref residency.TenantKeyRef) residency.CMKResolver {
	return residency.CMKResolverFunc(func(context.Context, uuid.UUID) (residency.TenantKeyRef, error) {
		return ref, nil
	})
}

func platformRegistry(t *testing.T) *residency.KeyProviderRegistry {
	t.Helper()
	plat, err := residency.NewLocalKeyProvider(residency.ProviderPlatform, bytes.Repeat([]byte{0xA1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := residency.NewKeyProviderRegistry(plat)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestCMKServicePlatformFallbackRoundTrip(t *testing.T) {
	tid := uuid.New()
	svc, err := residency.NewCMKService(
		refFn(residency.TenantKeyRef{}), // no CMK configured
		regionFn("eu-central-1"),
		platformRegistry(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	ec := residency.EncryptionContext{"plane": "telemetry"}
	dk, err := svc.GenerateDataKey(context.Background(), tid, ec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if dk.Wrapped.Kind != residency.ProviderPlatform {
		t.Fatalf("expected platform fallback, got %s", dk.Wrapped.Kind)
	}
	got, err := svc.UnwrapDataKey(context.Background(), tid, dk.Wrapped, ec)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dk.Plaintext) {
		t.Fatal("roundtrip mismatch")
	}
}

func awsRegistry(t *testing.T, region residency.Region, keyURI string) *residency.KeyProviderRegistry {
	t.Helper()
	plat, err := residency.NewLocalKeyProvider(residency.ProviderPlatform, bytes.Repeat([]byte{0xB2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aws, err := residency.NewLocalKeyProvider(
		residency.ProviderAWSKMS, bytes.Repeat([]byte{0xC3}, 32),
		residency.WithLocalKey(keyURI, bytes.Repeat([]byte{0xD4}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := residency.NewKeyProviderRegistry(plat, aws)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestCMKServiceRegionBindingFailsClosed(t *testing.T) {
	tid := uuid.New()
	keyURI := "arn:aws:kms:us-east-1:123456789012:key/abcd"
	ref := residency.TenantKeyRef{
		TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "us-east-1", KeyURI: keyURI}

	// Tenant residency is eu-central-1 but CMK lives in us-east-1.
	svc, _ := residency.NewCMKService(refFn(ref), regionFn("eu-central-1"),
		awsRegistry(t, "us-east-1", keyURI), nil)

	_, err := svc.GenerateDataKey(context.Background(), tid, nil)
	if !errors.Is(err, residency.ErrResidencyViolation) {
		t.Fatalf("CMK outside residency region must be rejected, got %v", err)
	}
}

func TestCMKServiceRegionBindingAllowsMatching(t *testing.T) {
	tid := uuid.New()
	keyURI := "arn:aws:kms:eu-central-1:123456789012:key/abcd"
	ref := residency.TenantKeyRef{
		TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1", KeyURI: keyURI}

	svc, _ := residency.NewCMKService(refFn(ref), regionFn("eu-central-1"),
		awsRegistry(t, "eu-central-1", keyURI), nil)

	dk, err := svc.GenerateDataKey(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("matching region CMK should be allowed: %v", err)
	}
	if dk.Wrapped.Kind != residency.ProviderAWSKMS || dk.Wrapped.KeyURI != keyURI {
		t.Fatalf("expected aws CMK wrap, got %+v", dk.Wrapped)
	}
}

func TestCMKServiceNoDesignationAllowsAnyRegion(t *testing.T) {
	tid := uuid.New()
	keyURI := "arn:aws:kms:us-east-1:123456789012:key/abcd"
	ref := residency.TenantKeyRef{
		TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "us-east-1", KeyURI: keyURI}

	svc, _ := residency.NewCMKService(refFn(ref), regionFn(""), // no residency designation
		awsRegistry(t, "us-east-1", keyURI), nil)

	if _, err := svc.GenerateDataKey(context.Background(), tid, nil); err != nil {
		t.Fatalf("CMK should be allowed when tenant has no residency designation: %v", err)
	}
}

func TestCMKServiceUnknownProviderFailsClosed(t *testing.T) {
	tid := uuid.New()
	ref := residency.TenantKeyRef{
		TenantID: tid, Kind: residency.ProviderGCPKMS, Region: "eu-central-1",
		KeyURI: "projects/sng/locations/europe-west3/keyRings/t/cryptoKeys/k"}

	// Registry only has platform — GCP is not wired.
	svc, _ := residency.NewCMKService(refFn(ref), regionFn("eu-central-1"), platformRegistry(t), nil)

	if _, err := svc.GenerateDataKey(context.Background(), tid, nil); !errors.Is(err, residency.ErrUnknownProvider) {
		t.Fatalf("unwired provider must fail closed, got %v", err)
	}
}

func TestCMKServiceResolverErrorFailsClosed(t *testing.T) {
	sentinel := errors.New("db down")
	svc, _ := residency.NewCMKService(
		residency.CMKResolverFunc(func(context.Context, uuid.UUID) (residency.TenantKeyRef, error) {
			return residency.TenantKeyRef{}, sentinel
		}),
		regionFn("eu-central-1"), platformRegistry(t), nil)

	if _, err := svc.GenerateDataKey(context.Background(), uuid.New(), nil); !errors.Is(err, sentinel) {
		t.Fatalf("resolver error must propagate fail-closed, got %v", err)
	}
}

func TestCMKServiceTenantBindingPreventsCrossTenantUnwrap(t *testing.T) {
	tenantA := uuid.New()
	tenantB := uuid.New()
	reg := platformRegistry(t)

	svcA, _ := residency.NewCMKService(refFn(residency.TenantKeyRef{}), regionFn(""), reg, nil)
	dk, err := svcA.GenerateDataKey(context.Background(), tenantA, residency.EncryptionContext{"plane": "telemetry"})
	if err != nil {
		t.Fatal(err)
	}
	// Tenant B tries to unwrap tenant A's DEK on the shared platform KEK.
	svcB, _ := residency.NewCMKService(refFn(residency.TenantKeyRef{}), regionFn(""), reg, nil)
	if _, err := svcB.UnwrapDataKey(context.Background(), tenantB, dk.Wrapped, residency.EncryptionContext{"plane": "telemetry"}); !errors.Is(err, residency.ErrUnwrapFailed) {
		t.Fatalf("cross-tenant unwrap must fail (tenant AAD), got %v", err)
	}
	// Tenant A unwraps fine.
	if _, err := svcA.UnwrapDataKey(context.Background(), tenantA, dk.Wrapped, residency.EncryptionContext{"plane": "telemetry"}); err != nil {
		t.Fatalf("owner unwrap should succeed: %v", err)
	}
}

func TestCMKServiceConflictingTenantContextRejected(t *testing.T) {
	tid := uuid.New()
	svc, _ := residency.NewCMKService(refFn(residency.TenantKeyRef{}), regionFn(""), platformRegistry(t), nil)
	// Caller pre-sets the reserved tenant_id to a different value.
	ec := residency.EncryptionContext{residency.ContextTenantID: uuid.New().String()}
	if _, err := svc.GenerateDataKey(context.Background(), tid, ec); !errors.Is(err, residency.ErrInvalidKeyRef) {
		t.Fatalf("conflicting tenant context must be rejected, got %v", err)
	}
}

// After a tenant rotates from platform-managed to a CMK, a DEK wrapped
// under the old platform KEK must still unwrap: unwrap routes by the
// wrapped envelope's kind, not the tenant's current KEK.
func TestCMKServiceUnwrapRoutesByWrappedKindAcrossRotation(t *testing.T) {
	tid := uuid.New()
	keyURI := "arn:aws:kms:eu-central-1:123456789012:key/abcd"
	reg := awsRegistry(t, "eu-central-1", keyURI)

	// Phase 1: no CMK — wrap under platform.
	svcBefore, _ := residency.NewCMKService(refFn(residency.TenantKeyRef{}), regionFn("eu-central-1"), reg, nil)
	ec := residency.EncryptionContext{"plane": "cold_storage"}
	dk, err := svcBefore.GenerateDataKey(context.Background(), tid, ec)
	if err != nil {
		t.Fatal(err)
	}
	if dk.Wrapped.Kind != residency.ProviderPlatform {
		t.Fatalf("phase 1 should wrap under platform, got %s", dk.Wrapped.Kind)
	}

	// Phase 2: tenant now has an aws CMK. Old platform-wrapped DEK must
	// still unwrap via the same service.
	svcAfter, _ := residency.NewCMKService(
		refFn(residency.TenantKeyRef{TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1", KeyURI: keyURI}),
		regionFn("eu-central-1"), reg, nil)

	got, err := svcAfter.UnwrapDataKey(context.Background(), tid, dk.Wrapped, ec)
	if err != nil {
		t.Fatalf("post-rotation unwrap of platform-wrapped DEK must succeed: %v", err)
	}
	if !bytes.Equal(got, dk.Plaintext) {
		t.Fatal("post-rotation unwrap mismatch")
	}

	// And a fresh wrap now uses the aws CMK.
	dk2, err := svcAfter.GenerateDataKey(context.Background(), tid, ec)
	if err != nil {
		t.Fatal(err)
	}
	if dk2.Wrapped.Kind != residency.ProviderAWSKMS {
		t.Fatalf("phase 2 should wrap under aws CMK, got %s", dk2.Wrapped.Kind)
	}
}

// recordingProvider is a TenantKeyProvider that captures the ref it is
// called with, so a test can assert what the CMKService passes down.
type recordingProvider struct {
	kind   residency.KeyProviderKind
	gotRef residency.TenantKeyRef
}

func (p *recordingProvider) Kind() residency.KeyProviderKind { return p.kind }

func (p *recordingProvider) GenerateDataKey(_ context.Context, ref residency.TenantKeyRef, _ residency.EncryptionContext) (residency.DataKey, error) {
	p.gotRef = ref
	return residency.DataKey{
		Plaintext: bytes.Repeat([]byte{0x01}, 32),
		Wrapped:   residency.WrappedDataKey{Kind: p.kind, KeyURI: ref.KeyURI, Ciphertext: []byte("ct")},
	}, nil
}

func (p *recordingProvider) WrapDataKey(_ context.Context, ref residency.TenantKeyRef, plaintext []byte, _ residency.EncryptionContext) (residency.WrappedDataKey, error) {
	p.gotRef = ref
	return residency.WrappedDataKey{Kind: p.kind, KeyURI: ref.KeyURI, Ciphertext: append([]byte("ct:"), plaintext...)}, nil
}

func (p *recordingProvider) UnwrapDataKey(_ context.Context, ref residency.TenantKeyRef, _ residency.WrappedDataKey, _ residency.EncryptionContext) ([]byte, error) {
	p.gotRef = ref
	return bytes.Repeat([]byte{0x01}, 32), nil
}

// TestCMKServiceCanonicalizesRefRegion asserts that the CMKService
// normalizes a resolver-supplied region before handing the ref to the
// provider, so the region on the struct is the canonical form rather
// than whatever case/whitespace the resolver returned.
func TestCMKServiceCanonicalizesRefRegion(t *testing.T) {
	tid := uuid.New()
	keyURI := "arn:aws:kms:eu-central-1:123456789012:key/abcd"
	rec := &recordingProvider{kind: residency.ProviderAWSKMS}
	reg, err := residency.NewKeyProviderRegistry(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Resolver returns a non-canonical region (mixed case + whitespace)
	// that normalizes to the tenant's designated region.
	ref := residency.TenantKeyRef{
		TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "  EU-Central-1 ", KeyURI: keyURI}
	svc, err := residency.NewCMKService(refFn(ref), regionFn("eu-central-1"), reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GenerateDataKey(context.Background(), tid, nil); err != nil {
		t.Fatalf("matching (post-normalization) region must be allowed: %v", err)
	}
	if got := rec.gotRef.Region; got != residency.Region("eu-central-1") {
		t.Fatalf("provider received non-canonical region %q, want %q", got, "eu-central-1")
	}
}

// TestCMKServiceReWrapDataKeyAuditTrail asserts that ReWrapDataKey
// re-seals a DEK onto the target KEK (decryptable afterward) AND emits a
// structured audit record naming the source→target KEK/region — the
// observability the method's skipped region-binding relies on — even
// though the tenant's resolver region is still the SOURCE.
func TestCMKServiceReWrapDataKeyAuditTrail(t *testing.T) {
	tid := uuid.New()
	targetKeyURI := "arn:aws:kms:eu-central-1:123456789012:key/abcd"
	target := residency.TenantKeyRef{
		TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1", KeyURI: targetKeyURI}

	capH := &capturingHandler{}
	// Resolver region is the SOURCE (us-east-1): ReWrapDataKey must not
	// enforce it against the eu-central-1 target, and must still audit.
	svc, err := residency.NewCMKService(
		refFn(residency.TenantKeyRef{}), // tenant uses the platform KEK at source
		regionFn("us-east-1"),
		awsRegistry(t, "eu-central-1", targetKeyURI),
		slog.New(capH))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ec := residency.EncryptionContext{"plane": "telemetry"}

	// Wrap a DEK under the source (platform) KEK, then re-wrap onto the
	// target AWS CMK.
	dk, err := svc.GenerateDataKey(ctx, tid, ec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if dk.Wrapped.Kind != residency.ProviderPlatform {
		t.Fatalf("source wrap kind = %q, want platform", dk.Wrapped.Kind)
	}
	rewrapped, err := svc.ReWrapDataKey(ctx, tid, dk.Wrapped, target, ec)
	if err != nil {
		t.Fatalf("re-wrap: %v", err)
	}
	if rewrapped.Kind != residency.ProviderAWSKMS || rewrapped.KeyURI != targetKeyURI {
		t.Fatalf("re-wrapped onto %+v, want aws_kms %s", rewrapped, targetKeyURI)
	}
	// The re-wrapped DEK still decrypts to the same plaintext.
	got, err := svc.UnwrapDataKey(ctx, tid, rewrapped, ec)
	if err != nil {
		t.Fatalf("unwrap re-wrapped: %v", err)
	}
	if !bytes.Equal(got, dk.Plaintext) {
		t.Fatal("re-wrap changed the DEK plaintext")
	}

	// Audit record names the source→target KEK and the tenant.
	attrs, ok := capH.attrsByMessage("residency: re-wrapped tenant DEK")
	if !ok {
		t.Fatal("no re-wrap audit record emitted")
	}
	want := map[string]string{
		"audit":          "cmk.rewrap",
		"tenant_id":      tid.String(),
		"source_kind":    string(residency.ProviderPlatform),
		"target_kind":    string(residency.ProviderAWSKMS),
		"target_region":  "eu-central-1",
		"target_key_uri": targetKeyURI,
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("audit attr %q = %q, want %q", k, attrs[k], v)
		}
	}
}

func TestCMKServiceConstructorValidation(t *testing.T) {
	if _, err := residency.NewCMKService(nil, regionFn(""), platformRegistry(t), nil); err == nil {
		t.Fatal("nil refs must be rejected")
	}
	if _, err := residency.NewCMKService(refFn(residency.TenantKeyRef{}), nil, platformRegistry(t), nil); err == nil {
		t.Fatal("nil regions must be rejected")
	}
	if _, err := residency.NewCMKService(refFn(residency.TenantKeyRef{}), regionFn(""), nil, nil); err == nil {
		t.Fatal("nil registry must be rejected")
	}
}
