package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// mobileKey returns a fresh base64 (std) Ed25519 public key string, as
// the session token's device_key claim would carry.
func mobileKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func boolPtr(b bool) *bool { return &b }

func TestEnrollMobileDevice_CreateThenIdempotentUpdate(t *testing.T) {
	t.Parallel()
	svc, store, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)

	res, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey:   key,
		Platform:    repository.DevicePlatformIOS,
		Name:        "Ken's iPhone",
		OIDCSubject: "google|123",
	})
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if !res.Created {
		t.Fatalf("first enroll Created = false, want true")
	}
	if res.Device.Platform != repository.DevicePlatformIOS {
		t.Errorf("platform = %q", res.Device.Platform)
	}
	if res.Device.Status != repository.DeviceStatusActive {
		t.Errorf("status = %q, want active", res.Device.Status)
	}
	if res.Device.EnrolledAt == nil {
		t.Error("EnrolledAt not stamped")
	}
	if res.Device.PublicKeyEd25519 != key {
		t.Errorf("public key = %q, want %q", res.Device.PublicKeyEd25519, key)
	}

	// Re-enroll the same key: must UPDATE (not duplicate) → Created=false,
	// same device id.
	res2, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey:   key,
		Platform:    repository.DevicePlatformIOS,
		OIDCSubject: "google|123",
	})
	if err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if res2.Created {
		t.Errorf("re-enroll Created = true, want false (idempotent)")
	}
	if res2.Device.ID != res.Device.ID {
		t.Errorf("re-enroll created a new device id %s, want %s", res2.Device.ID, res.Device.ID)
	}

	// Exactly one device exists for the tenant (idempotent re-enroll
	// did not duplicate).
	page, err := memory.NewDeviceRepository(store).List(ctx, tenantID, repository.DeviceListFilter{}, repository.Page{})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("device count = %d, want 1", len(page.Items))
	}
}

func TestEnrollMobileDevice_RejectsNonMobilePlatform(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	_, err := svc.EnrollMobileDevice(context.Background(), tenantID, identity.MobileEnrollInput{
		DeviceKey: mobileKey(t),
		Platform:  repository.DevicePlatformMacOS,
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestEnrollMobileDevice_RejectsEmptyDeviceKey(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	_, err := svc.EnrollMobileDevice(context.Background(), tenantID, identity.MobileEnrollInput{
		DeviceKey: "",
		Platform:  repository.DevicePlatformIOS,
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestEnrollMobileDevice_RejectsPlatformChangeOnReenroll(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)

	if _, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// Same key, different platform — a device key is bound to one
	// physical device, so this is a client error.
	_, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformAndroid,
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestEnrollMobileDevice_TenantIsolation(t *testing.T) {
	t.Parallel()
	svc, store, tenantA := newSvc(t)
	ctx := context.Background()
	// Seed a second tenant in the same store.
	tenantB, err := memory.NewTenantRepository(store).Create(ctx, repository.Tenant{
		Name: "B", Slug: "tenant-b", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	key := mobileKey(t)

	if _, err := svc.EnrollMobileDevice(ctx, tenantA, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	}); err != nil {
		t.Fatalf("enroll A: %v", err)
	}
	// The SAME key under tenant B is a distinct device (per-tenant
	// uniqueness), so it must be a fresh create, not an idempotent hit
	// on tenant A's device.
	resB, err := svc.EnrollMobileDevice(ctx, tenantB.ID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	})
	if err != nil {
		t.Fatalf("enroll B: %v", err)
	}
	if !resB.Created {
		t.Errorf("tenant B enroll Created = false; key leaked across tenants")
	}
}

func TestEnrollMobileDevice_InitialPostureValidated(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	// Android device supplying an iOS-only jailbroken signal must be
	// rejected even on the enrolment path.
	_, err := svc.EnrollMobileDevice(context.Background(), tenantID, identity.MobileEnrollInput{
		DeviceKey: mobileKey(t),
		Platform:  repository.DevicePlatformAndroid,
		Posture:   &repository.Posture{Jailbroken: boolPtr(false)},
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestReportMobilePosture_HappyPath(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)
	if _, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	dev, err := svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
		DeviceKey: key,
		Posture: repository.Posture{
			OSVersion:      "17.5.1",
			PasscodeSet:    boolPtr(true),
			Jailbroken:     boolPtr(false),
			BiometricReady: boolPtr(true),
		},
	})
	if err != nil {
		t.Fatalf("report posture: %v", err)
	}
	if dev.Posture.OSVersion != "17.5.1" {
		t.Errorf("os version = %q", dev.Posture.OSVersion)
	}
	if dev.Posture.CollectedAt == nil {
		t.Error("CollectedAt not stamped when omitted")
	}
}

func TestReportMobilePosture_DeviceNotEnrolled(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	_, err := svc.ReportMobilePosture(context.Background(), tenantID, identity.MobilePostureInput{
		DeviceKey: mobileKey(t),
		Posture:   repository.Posture{OSVersion: "17.0"},
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestReportMobilePosture_CrossPlatformSignalRejected(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)
	if _, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// root_detected is Android-only; reporting it for an iOS device
	// is a coherence error.
	_, err := svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
		DeviceKey: key,
		Posture:   repository.Posture{RootDetected: boolPtr(true)},
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestReportMobilePosture_TimestampWindow(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)
	if _, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformAndroid,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	now := time.Now().UTC()
	cases := []struct {
		name      string
		collected time.Time
		wantErr   bool
	}{
		{"recent", now.Add(-1 * time.Minute), false},
		{"far_future", now.Add(1 * time.Hour), true},
		{"stale", now.Add(-48 * time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collected := tc.collected
			_, err := svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
				DeviceKey: key,
				Posture:   repository.Posture{CollectedAt: &collected, RootDetected: boolPtr(false)},
			})
			if tc.wantErr && !errors.Is(err, repository.ErrInvalidArgument) {
				t.Errorf("err = %v, want ErrInvalidArgument", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}
