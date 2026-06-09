package residency_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/residency"
)

func mustMaster(t *testing.T, b byte) []byte {
	t.Helper()
	return bytes.Repeat([]byte{b}, 32)
}

func TestEncryptionContextCanonicalIsDeterministicAndOrderIndependent(t *testing.T) {
	a := residency.EncryptionContext{"tenant_id": "t1", "plane": "telemetry"}
	b := residency.EncryptionContext{"plane": "telemetry", "tenant_id": "t1"}
	if !bytes.Equal(a.Canonical(), b.Canonical()) {
		t.Fatalf("canonical encoding must be order-independent: %s vs %s", a.Canonical(), b.Canonical())
	}
	c := residency.EncryptionContext{"tenant_id": "t2", "plane": "telemetry"}
	if bytes.Equal(a.Canonical(), c.Canonical()) {
		t.Fatalf("different contexts must encode differently")
	}
	if got := (residency.EncryptionContext{}).Canonical(); string(got) != "{}" {
		t.Fatalf("empty context canonical = %q, want {}", got)
	}
}

func TestTenantKeyRefValidate(t *testing.T) {
	tid := uuid.New()
	cases := []struct {
		name    string
		ref     residency.TenantKeyRef
		wantErr bool
	}{
		{"platform empty uri", residency.TenantKeyRef{TenantID: tid, Kind: residency.ProviderPlatform}, false},
		{"empty tenant", residency.TenantKeyRef{Kind: residency.ProviderPlatform}, true},
		{"aws valid arn", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1",
			KeyURI: "arn:aws:kms:eu-central-1:123456789012:key/abcd-1234"}, false},
		{"aws alias arn", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1",
			KeyURI: "arn:aws:kms:eu-central-1:123456789012:alias/tenant-cmk"}, false},
		{"aws bad arn", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1",
			KeyURI: "not-an-arn"}, true},
		{"aws empty uri", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "eu-central-1"}, true},
		{"azure valid", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAzureKV, Region: "eu-central-1",
			KeyURI: "https://sng-vault.vault.azure.net/keys/tenant-cmk/0123456789abcdef0123456789abcdef"}, false},
		{"azure no version", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAzureKV, Region: "eu-central-1",
			KeyURI: "https://sng-vault.vault.azure.net/keys/tenant-cmk"}, false},
		{"gcp valid", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderGCPKMS, Region: "eu-central-1",
			KeyURI: "projects/sng/locations/europe-west3/keyRings/tenants/cryptoKeys/cmk"}, false},
		{"gcp bad", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderGCPKMS, Region: "eu-central-1",
			KeyURI: "projects/sng/cryptoKeys/cmk"}, true},
		{"unknown kind", residency.TenantKeyRef{TenantID: tid, Kind: "vault_transit", Region: "eu-central-1", KeyURI: "x"}, true},
		{"cmk invalid region", residency.TenantKeyRef{
			TenantID: tid, Kind: residency.ProviderAWSKMS, Region: "EU CENTRAL",
			KeyURI: "arn:aws:kms:eu-central-1:123456789012:key/abcd"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && !errors.Is(err, residency.ErrInvalidKeyRef) {
				t.Fatalf("error should wrap ErrInvalidKeyRef, got %v", err)
			}
		})
	}
}

func TestTenantKeyRefIsCMK(t *testing.T) {
	if (residency.TenantKeyRef{}).IsCMK() {
		t.Fatal("zero ref must not be CMK")
	}
	if (residency.TenantKeyRef{Kind: residency.ProviderPlatform}).IsCMK() {
		t.Fatal("platform ref must not be CMK")
	}
	if !(residency.TenantKeyRef{Kind: residency.ProviderAWSKMS}).IsCMK() {
		t.Fatal("aws ref must be CMK")
	}
}

func TestLocalProviderRoundTrip(t *testing.T) {
	p, err := residency.NewLocalKeyProvider(residency.ProviderPlatform, mustMaster(t, 0x11))
	if err != nil {
		t.Fatal(err)
	}
	tid := uuid.New()
	ref := residency.TenantKeyRef{TenantID: tid, Kind: residency.ProviderPlatform}
	ec := residency.EncryptionContext{"tenant_id": tid.String(), "plane": "cold_storage"}

	dk, err := p.GenerateDataKey(context.Background(), ref, ec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(dk.Plaintext) != 32 {
		t.Fatalf("dek len = %d, want 32", len(dk.Plaintext))
	}
	if bytes.Equal(dk.Plaintext, dk.Wrapped.Ciphertext) {
		t.Fatal("wrapped ciphertext must not equal plaintext dek")
	}

	got, err := p.UnwrapDataKey(context.Background(), ref, dk.Wrapped, ec)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dk.Plaintext) {
		t.Fatal("unwrapped dek differs from generated dek")
	}
}

func TestLocalProviderRejectsWrongContext(t *testing.T) {
	p, _ := residency.NewLocalKeyProvider(residency.ProviderPlatform, mustMaster(t, 0x22))
	ref := residency.TenantKeyRef{TenantID: uuid.New(), Kind: residency.ProviderPlatform}
	dk, err := p.GenerateDataKey(context.Background(), ref, residency.EncryptionContext{"tenant_id": "a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.UnwrapDataKey(context.Background(), ref, dk.Wrapped, residency.EncryptionContext{"tenant_id": "b"})
	if !errors.Is(err, residency.ErrUnwrapFailed) {
		t.Fatalf("wrong AAD must fail with ErrUnwrapFailed, got %v", err)
	}
}

func TestLocalProviderRejectsTamperedCiphertext(t *testing.T) {
	p, _ := residency.NewLocalKeyProvider(residency.ProviderPlatform, mustMaster(t, 0x33))
	ref := residency.TenantKeyRef{TenantID: uuid.New(), Kind: residency.ProviderPlatform}
	ec := residency.EncryptionContext{"tenant_id": "a"}
	dk, _ := p.GenerateDataKey(context.Background(), ref, ec)
	dk.Wrapped.Ciphertext[len(dk.Wrapped.Ciphertext)-1] ^= 0xFF
	if _, err := p.UnwrapDataKey(context.Background(), ref, dk.Wrapped, ec); !errors.Is(err, residency.ErrUnwrapFailed) {
		t.Fatalf("tampered ciphertext must fail, got %v", err)
	}
}

func TestLocalProviderKindMismatch(t *testing.T) {
	p, _ := residency.NewLocalKeyProvider(residency.ProviderPlatform, mustMaster(t, 0x44))
	ref := residency.TenantKeyRef{TenantID: uuid.New(), Kind: residency.ProviderAWSKMS}
	if _, err := p.GenerateDataKey(context.Background(), ref, nil); !errors.Is(err, residency.ErrProviderKindMismatch) {
		t.Fatalf("kind mismatch must fail, got %v", err)
	}
}

func TestLocalProviderNamedKeyMissingFailsClosed(t *testing.T) {
	p, _ := residency.NewLocalKeyProvider(residency.ProviderAWSKMS, mustMaster(t, 0x55))
	ref := residency.TenantKeyRef{
		TenantID: uuid.New(), Kind: residency.ProviderAWSKMS, Region: "eu-central-1",
		KeyURI: "arn:aws:kms:eu-central-1:123456789012:key/unregistered"}
	if _, err := p.GenerateDataKey(context.Background(), ref, nil); !errors.Is(err, residency.ErrInvalidKeyRef) {
		t.Fatalf("unregistered named key must fail closed, got %v", err)
	}
}

func TestLocalProviderRejectsBadMaster(t *testing.T) {
	if _, err := residency.NewLocalKeyProvider(residency.ProviderPlatform, []byte("short")); err == nil {
		t.Fatal("expected error for non-32-byte master")
	}
	if _, err := residency.NewLocalKeyProvider("", mustMaster(t, 1)); err == nil {
		t.Fatal("expected error for empty kind")
	}
}

func TestRegistry(t *testing.T) {
	plat, _ := residency.NewLocalKeyProvider(residency.ProviderPlatform, mustMaster(t, 1))
	aws, _ := residency.NewLocalKeyProvider(residency.ProviderAWSKMS, mustMaster(t, 2))

	reg, err := residency.NewKeyProviderRegistry(plat, aws)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.For(residency.ProviderPlatform); err != nil {
		t.Fatalf("platform should resolve: %v", err)
	}
	if _, err := reg.For(residency.ProviderGCPKMS); !errors.Is(err, residency.ErrUnknownProvider) {
		t.Fatalf("unregistered kind must be ErrUnknownProvider, got %v", err)
	}
	if len(reg.Kinds()) != 2 {
		t.Fatalf("Kinds() = %v, want 2 entries", reg.Kinds())
	}

	// Duplicate kind rejected.
	plat2, _ := residency.NewLocalKeyProvider(residency.ProviderPlatform, mustMaster(t, 3))
	if _, err := residency.NewKeyProviderRegistry(plat, plat2); err == nil {
		t.Fatal("duplicate provider kind must be rejected")
	}
	// Nil provider rejected.
	if _, err := residency.NewKeyProviderRegistry(nil); err == nil {
		t.Fatal("nil provider must be rejected")
	}
}
