package identity_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

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

// TestReportMobilePosture_AdvancesLastSeen asserts a posture report
// doubles as a heartbeat: a freshly enrolled device has no last_seen_at
// (enrolment does not stamp it), and reporting posture sets it.
func TestReportMobilePosture_AdvancesLastSeen(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)
	enrolled, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if enrolled.Device.LastSeenAt != nil {
		t.Fatalf("precondition: enrolled device LastSeenAt = %v, want nil", enrolled.Device.LastSeenAt)
	}

	reported, err := svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
		DeviceKey: key,
		Posture:   repository.Posture{OSVersion: "17.5.1"},
	})
	if err != nil {
		t.Fatalf("report posture: %v", err)
	}
	if reported.LastSeenAt == nil {
		t.Error("LastSeenAt = nil after posture report, want it stamped (posture report is proof-of-liveness)")
	}
}

// TestReportMobilePosture_DesktopSignalRejected asserts that desktop/
// general posture signals (not part of the mobile contract) are
// rejected for a mobile device rather than silently persisted.
func TestReportMobilePosture_DesktopSignalRejected(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	key := mobileKey(t)
	if _, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	cases := []struct {
		name    string
		posture repository.Posture
	}{
		{"disk_encrypted", repository.Posture{DiskEncrypted: boolPtr(true)}},
		{"firewall_enabled", repository.Posture{FirewallEnabled: boolPtr(true)}},
		{"screen_lock", repository.Posture{ScreenLock: boolPtr(true)}},
		{"patch_level", repository.Posture{PatchLevel: "2025-05"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
				DeviceKey: key,
				Posture:   tc.posture,
			})
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Errorf("err = %v, want ErrInvalidArgument", err)
			}
		})
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

// suspendDevice flips an enrolled device to the given admin-controlled
// status directly through the repository, simulating an admin
// suspend/delete out-of-band from the mobile self-service path.
func suspendDevice(t *testing.T, store *memory.Store, tenantID, id uuid.UUID, status repository.DeviceStatus) {
	t.Helper()
	if _, err := memory.NewDeviceRepository(store).UpdateStatus(context.Background(), tenantID, id, status); err != nil {
		t.Fatalf("set device status %s: %v", status, err)
	}
}

func TestEnrollMobileDevice_RejectsReenrollOfDisabledDevice(t *testing.T) {
	t.Parallel()
	for _, status := range []repository.DeviceStatus{
		repository.DeviceStatusSuspended,
		repository.DeviceStatusDeleted,
	} {
		t.Run(string(status), func(t *testing.T) {
			svc, store, tenantID := newSvc(t)
			ctx := context.Background()
			key := mobileKey(t)

			res, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
				DeviceKey: key, Platform: repository.DevicePlatformIOS,
			})
			if err != nil {
				t.Fatalf("enroll: %v", err)
			}
			// Admin suspends/deletes the device out-of-band.
			suspendDevice(t, store, tenantID, res.Device.ID, status)

			// A still-valid session must not self-reinstate it.
			_, err = svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
				DeviceKey: key, Platform: repository.DevicePlatformIOS,
			})
			if !errors.Is(err, repository.ErrForbidden) {
				t.Fatalf("re-enroll err = %v, want ErrForbidden", err)
			}
			// The device stays disabled (not flipped back to active).
			got, err := memory.NewDeviceRepository(store).GetByPublicKey(ctx, tenantID, key)
			if err != nil {
				t.Fatalf("get device: %v", err)
			}
			if got.Status != status {
				t.Errorf("status = %q, want %q (unchanged)", got.Status, status)
			}
		})
	}
}

func TestReportMobilePosture_RejectsDisabledDevice(t *testing.T) {
	t.Parallel()
	for _, status := range []repository.DeviceStatus{
		repository.DeviceStatusSuspended,
		repository.DeviceStatusDeleted,
	} {
		t.Run(string(status), func(t *testing.T) {
			svc, store, tenantID := newSvc(t)
			ctx := context.Background()
			key := mobileKey(t)

			res, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
				DeviceKey: key, Platform: repository.DevicePlatformIOS,
			})
			if err != nil {
				t.Fatalf("enroll: %v", err)
			}
			suspendDevice(t, store, tenantID, res.Device.ID, status)

			_, err = svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
				DeviceKey: key,
				Posture:   repository.Posture{OSVersion: "17.5.1", PasscodeSet: boolPtr(true)},
			})
			if !errors.Is(err, repository.ErrForbidden) {
				t.Fatalf("report posture err = %v, want ErrForbidden", err)
			}
		})
	}
}

// TestReportMobilePosture_AdvancesUpdatedAt guards against returning a
// stale updated_at: the posture-report response must carry the
// timestamp advanced by the store on UpdatePosture (mirroring the
// Postgres devices_set_updated_at trigger), not the value read before
// the update.
func TestReportMobilePosture_AdvancesUpdatedAt(t *testing.T) {
	t.Parallel()
	svc, store, tenantID := newSvc(t)
	ctx := context.Background()

	// Deterministic, strictly-increasing clock so updated_at changes
	// observably across operations.
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var ticks int64
	store.SetClock(func() time.Time {
		ticks++
		return base.Add(time.Duration(ticks) * time.Second)
	})

	key := mobileKey(t)
	enrolled, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	reported, err := svc.ReportMobilePosture(ctx, tenantID, identity.MobilePostureInput{
		DeviceKey: key,
		Posture:   repository.Posture{OSVersion: "17.5.1", PasscodeSet: boolPtr(true)},
	})
	if err != nil {
		t.Fatalf("report posture: %v", err)
	}

	// The returned device must carry the advanced updated_at, not the
	// stale value from the pre-update lookup.
	if !reported.UpdatedAt.After(enrolled.Device.UpdatedAt) {
		t.Errorf("updated_at = %s, want after enroll updated_at %s",
			reported.UpdatedAt, enrolled.Device.UpdatedAt)
	}
	// And it must match exactly what the repository persisted.
	stored, err := memory.NewDeviceRepository(store).Get(ctx, tenantID, reported.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if !reported.UpdatedAt.Equal(stored.UpdatedAt) {
		t.Errorf("returned updated_at %s != stored %s (stale response)",
			reported.UpdatedAt, stored.UpdatedAt)
	}
}

// TestMobileDeviceRevoked covers the live-status check behind the
// auth-middleware kill-switch: active devices may proceed, while
// suspended/deleted/absent ones are reported revoked.
func TestMobileDeviceRevoked(t *testing.T) {
	t.Parallel()
	svc, store, tenantID := newSvc(t)
	ctx := context.Background()
	devices := memory.NewDeviceRepository(store)
	key := mobileKey(t)

	res, err := svc.EnrollMobileDevice(ctx, tenantID, identity.MobileEnrollInput{
		DeviceKey:   key,
		Platform:    repository.DevicePlatformAndroid,
		OIDCSubject: "google|abc",
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	// Active device: not revoked.
	if revoked, err := svc.MobileDeviceRevoked(ctx, tenantID, key); err != nil || revoked {
		t.Fatalf("active device: revoked=%v err=%v, want false/nil", revoked, err)
	}

	// Unknown key (device not yet enrolled): NOT revoked — otherwise
	// the middleware kill-switch would 403 first-time enrolment before
	// the request reaches the enrol handler. Suspend/delete are soft
	// transitions that keep the row, so a genuinely disabled device is
	// still resolved and caught by status below.
	if revoked, err := svc.MobileDeviceRevoked(ctx, tenantID, mobileKey(t)); err != nil || revoked {
		t.Fatalf("unknown key: revoked=%v err=%v, want false/nil", revoked, err)
	}

	// Empty/zero identifiers are left for the endpoint's own
	// validation, never treated as revoked.
	if revoked, err := svc.MobileDeviceRevoked(ctx, tenantID, ""); err != nil || revoked {
		t.Fatalf("empty key: revoked=%v err=%v, want false/nil", revoked, err)
	}
	if revoked, err := svc.MobileDeviceRevoked(ctx, uuid.Nil, key); err != nil || revoked {
		t.Fatalf("nil tenant: revoked=%v err=%v, want false/nil", revoked, err)
	}

	for _, status := range []repository.DeviceStatus{
		repository.DeviceStatusSuspended,
		repository.DeviceStatusDeleted,
	} {
		if _, err := devices.UpdateStatus(ctx, tenantID, res.Device.ID, status); err != nil {
			t.Fatalf("set status %s: %v", status, err)
		}
		revoked, err := svc.MobileDeviceRevoked(ctx, tenantID, key)
		if err != nil || !revoked {
			t.Errorf("status %s: revoked=%v err=%v, want true/nil", status, revoked, err)
		}
	}
}

// raceDeviceRepo wraps a DeviceRepository to reproduce an admin
// suspend/delete landing in the TOCTOU window between the device-status
// read and the re-activation write in reactivateMobileDevice. The first
// time GetByPublicKey returns a still-pending device, it suspends that
// device out-of-band in the backing store but hands back the stale
// pre-suspend snapshot — exactly what a racing admin action would do.
type raceDeviceRepo struct {
	repository.DeviceRepository
	suspendedOnce bool
}

func (r *raceDeviceRepo) GetByPublicKey(ctx context.Context, tenantID uuid.UUID, key string) (repository.Device, error) {
	dev, err := r.DeviceRepository.GetByPublicKey(ctx, tenantID, key)
	if err == nil && !r.suspendedOnce && dev.Status == repository.DeviceStatusPending {
		r.suspendedOnce = true
		if _, serr := r.UpdateStatus(ctx, tenantID, dev.ID, repository.DeviceStatusSuspended); serr != nil {
			return repository.Device{}, serr
		}
	}
	return dev, err
}

// TestEnrollMobileDevice_ReactivationLosesRaceToAdminSuspend guards the
// TOCTOU fix: reactivateMobileDevice now re-activates via a conditional
// TransitionStatus(from: observed status) rather than an unconditional
// UpdateStatus. When an admin suspend lands between the disabled-check
// read and the write, the compare-and-swap must FAIL (the row is no
// longer pending) so the device is NOT silently reinstated.
func TestEnrollMobileDevice_ReactivationLosesRaceToAdminSuspend(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Tenant", Slug: "tenant", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	ctx := context.Background()
	devices := memory.NewDeviceRepository(s)
	key := mobileKey(t)

	// Seed a pending device for the key so enrolment takes the
	// reactivation (pending -> active) path.
	if _, err := devices.Create(ctx, tn.ID, repository.Device{
		Name: "iphone", Platform: repository.DevicePlatformIOS, PublicKeyEd25519: key,
		Status: repository.DeviceStatusPending,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	svc := identity.New(&raceDeviceRepo{DeviceRepository: devices}, memory.NewClaimTokenRepository(s), memory.NewAuditLogRepository(s), nil)

	_, err = svc.EnrollMobileDevice(ctx, tn.ID, identity.MobileEnrollInput{
		DeviceKey: key, Platform: repository.DevicePlatformIOS,
	})
	if !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("re-enrol racing an admin suspend: err=%v, want ErrForbidden", err)
	}

	// The device must remain suspended — the racing reactivation must
	// not have clobbered the admin's action.
	got, gerr := devices.GetByPublicKey(ctx, tn.ID, key)
	if gerr != nil {
		t.Fatalf("lookup after race: %v", gerr)
	}
	if got.Status != repository.DeviceStatusSuspended {
		t.Fatalf("device status after race = %q, want suspended (admin suspend must survive)", got.Status)
	}
}

// TestDeviceRepository_TransitionStatus_Memory covers the conditional
// transition primitive directly: a CAS that matches succeeds (and
// stamps enrolled_at on the active transition), a stale `from` is
// rejected with ErrForbidden, and an unknown id is ErrNotFound.
func TestDeviceRepository_TransitionStatus_Memory(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Tenant", Slug: "tenant", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	ctx := context.Background()
	devices := memory.NewDeviceRepository(s)
	dev, err := devices.Create(ctx, tn.ID, repository.Device{
		Name: "d", Platform: repository.DevicePlatformAndroid,
		PublicKeyEd25519: mobileKey(t), Status: repository.DeviceStatusPending,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Matching CAS pending -> active succeeds and stamps enrolled_at.
	out, err := devices.TransitionStatus(ctx, tn.ID, dev.ID, repository.DeviceStatusPending, repository.DeviceStatusActive)
	if err != nil {
		t.Fatalf("matching transition: %v", err)
	}
	if out.Status != repository.DeviceStatusActive || out.EnrolledAt == nil {
		t.Fatalf("after transition: status=%q enrolled_at=%v", out.Status, out.EnrolledAt)
	}

	// Stale precondition (device is now active, not pending) -> Forbidden.
	if _, err := devices.TransitionStatus(ctx, tn.ID, dev.ID, repository.DeviceStatusPending, repository.DeviceStatusActive); !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("stale-from transition: err=%v, want ErrForbidden", err)
	}

	// Unknown id -> NotFound.
	if _, err := devices.TransitionStatus(ctx, tn.ID, uuid.New(), repository.DeviceStatusActive, repository.DeviceStatusSuspended); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unknown id transition: err=%v, want ErrNotFound", err)
	}
}
