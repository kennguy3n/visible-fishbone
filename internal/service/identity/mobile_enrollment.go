package identity

// mobile_enrollment.go implements the device-bound mobile
// self-service flows that sit on top of the OIDC native-SSO session
// (oidc.go). A mobile agent first exchanges its IdP ID token + device
// key for an SNG session JWT (OIDCService.mintSession); that JWT
// carries `token_type: "mobile"` and the base64 Ed25519 `device_key`.
// Armed with it, the agent can:
//
//   - EnrollMobileDevice — register itself as an ios/android Device
//     bound to its device_key WITHOUT a claim token (claim tokens are
//     the desktop/general path; mobile authenticates via OIDC). The
//     operation is idempotent on (tenant_id, device_key): re-enrolling
//     the same key updates the existing device rather than duplicating.
//   - ReportMobilePosture — push a posture snapshot that lands on the
//     device the session is bound to (resolved from device_key, so a
//     device can only ever write its OWN posture).
//
// Both methods live on the existing identity.Service because it
// already owns the device repository + audit log and the appendAudit
// helper — there is one identity service that owns device lifecycle,
// and mobile enrolment is just another lifecycle entry point.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

const (
	// maxPostureClockSkew bounds how far a posture snapshot's
	// CollectedAt may sit in the FUTURE relative to the control
	// plane's clock before it is rejected. Mobile devices have
	// independent (occasionally wrong) clocks, so a small tolerance
	// avoids spurious rejections without accepting nonsensical
	// far-future timestamps.
	maxPostureClockSkew = 5 * time.Minute
	// maxPostureAge bounds how far in the PAST CollectedAt may sit
	// before the snapshot is rejected as stale. Posture drives ZTNA
	// access decisions, so an old snapshot must not be accepted as
	// current — the agent should re-collect and resubmit.
	maxPostureAge = 24 * time.Hour
)

// MobileEnrollInput is the validated input to EnrollMobileDevice. The
// authoritative device key comes from the verified session JWT (the
// handler reads it off middleware.MobileClaims), NOT from untrusted
// request fields.
type MobileEnrollInput struct {
	// DeviceKey is the base64 Ed25519 public key from the session
	// token's `device_key` claim — the device the session is bound to.
	DeviceKey string
	// Platform is the mobile OS the device is enrolling as; must be
	// ios or android.
	Platform repository.DevicePlatform
	// Name is an optional human-friendly device label. When empty a
	// deterministic default is derived from the platform.
	Name string
	// OIDCSubject is the upstream IdP subject (`oidc_sub`), recorded
	// in the audit trail so the device is attributable to a user even
	// though the devices table has no user FK.
	OIDCSubject string
	// Actor is the SNG user UUID the session resolved to, stamped as
	// the audit actor. nil when the session has no SNG user binding.
	Actor *uuid.UUID
	// Posture is an optional initial posture snapshot. nil means "no
	// posture supplied"; a non-nil snapshot is validated for
	// platform coherence + timestamp sanity like a posture report.
	Posture *repository.Posture
}

// MobileEnrollResult reports the enrolled device and whether it was
// freshly created (true → HTTP 201) or an idempotent update of an
// already-enrolled device (false → HTTP 200).
type MobileEnrollResult struct {
	Device  repository.Device
	Created bool
}

// EnrollMobileDevice registers (or idempotently re-activates) the
// calling mobile device, bound to the device key from its session.
//
// Idempotency: the device is looked up by (tenant_id, device_key). If
// it already exists it is re-activated (and its posture refreshed when
// a snapshot is supplied) and returned with Created=false. Otherwise a
// new active device is created with Created=true. A create that loses
// a race to a concurrent first-enrolment surfaces as ErrConflict from
// the repository (the partial unique index in migration 035); we
// recover by re-reading the now-existing device and taking the update
// path, so concurrent first-enrolments converge on a single device.
func (svc *Service) EnrollMobileDevice(
	ctx context.Context,
	tenantID uuid.UUID,
	in MobileEnrollInput,
) (MobileEnrollResult, error) {
	if tenantID == uuid.Nil {
		return MobileEnrollResult{}, repository.ErrInvalidArgument
	}
	if in.DeviceKey == "" {
		return MobileEnrollResult{}, fmt.Errorf("device key is required: %w", repository.ErrInvalidArgument)
	}
	if !in.Platform.IsMobile() {
		return MobileEnrollResult{}, fmt.Errorf("platform %q is not a mobile platform: %w", in.Platform, repository.ErrInvalidArgument)
	}

	now := svc.nowFunc()
	var initialPosture repository.Posture
	if in.Posture != nil {
		p, err := validateMobilePosture(*in.Posture, in.Platform, now)
		if err != nil {
			return MobileEnrollResult{}, err
		}
		initialPosture = p
	}

	// Idempotent fast path: device already enrolled for this key.
	if existing, err := svc.devices.GetByPublicKey(ctx, tenantID, in.DeviceKey); err == nil {
		dev, uerr := svc.reactivateMobileDevice(ctx, tenantID, existing, in, initialPosture)
		if uerr != nil {
			return MobileEnrollResult{}, uerr
		}
		return MobileEnrollResult{Device: dev, Created: false}, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return MobileEnrollResult{}, err
	}

	name := in.Name
	if name == "" {
		name = string(in.Platform) + " device"
	}
	created, err := svc.devices.Create(ctx, tenantID, repository.Device{
		Name:             name,
		Platform:         in.Platform,
		PublicKeyEd25519: in.DeviceKey,
		Status:           repository.DeviceStatusActive,
		EnrolledAt:       &now,
		Posture:          initialPosture,
	})
	if err != nil {
		// Lost the create race to a concurrent first-enrolment of the
		// same key (unique-index violation → ErrConflict). The device
		// now exists; converge by re-reading it and taking the update
		// path so both callers end up with the same single device.
		if errors.Is(err, repository.ErrConflict) {
			existing, gerr := svc.devices.GetByPublicKey(ctx, tenantID, in.DeviceKey)
			if gerr != nil {
				return MobileEnrollResult{}, err
			}
			dev, uerr := svc.reactivateMobileDevice(ctx, tenantID, existing, in, initialPosture)
			if uerr != nil {
				return MobileEnrollResult{}, uerr
			}
			return MobileEnrollResult{Device: dev, Created: false}, nil
		}
		return MobileEnrollResult{}, err
	}

	svc.logAuditErr(svc.appendAudit(ctx, tenantID, in.Actor, "device.mobile_enrolled", "device", &created.ID,
		mobileAuditDetails(in.OIDCSubject, in.Platform)))
	return MobileEnrollResult{Device: created, Created: true}, nil
}

// reactivateMobileDevice performs the idempotent-update branch of
// enrolment: it rejects a platform change (the device key is bound to
// one physical device, whose OS does not change under it), re-activates
// a non-active device, refreshes posture when a snapshot is supplied,
// and returns the resulting device.
func (svc *Service) reactivateMobileDevice(
	ctx context.Context,
	tenantID uuid.UUID,
	existing repository.Device,
	in MobileEnrollInput,
	initialPosture repository.Posture,
) (repository.Device, error) {
	if existing.Platform != in.Platform {
		// The device key is bound to one physical device whose OS does
		// not change under it, so a platform change is a client error
		// (400) — not a uniqueness conflict. Surfacing it as
		// invalid_argument also lets the descriptive message reach the
		// caller (WriteRepositoryError echoes ErrInvalidArgument text).
		return repository.Device{}, fmt.Errorf(
			"device key already enrolled as %q, cannot re-enroll as %q: %w",
			existing.Platform, in.Platform, repository.ErrInvalidArgument)
	}

	dev := existing
	// Re-activate if the device was suspended/pending or never had its
	// enrolment timestamp stamped. UpdateStatus stamps enrolled_at on
	// the active transition when it is still null.
	if existing.Status != repository.DeviceStatusActive || existing.EnrolledAt == nil {
		updated, err := svc.devices.UpdateStatus(ctx, tenantID, existing.ID, repository.DeviceStatusActive)
		if err != nil {
			return repository.Device{}, err
		}
		dev = updated
	}

	if in.Posture != nil {
		if err := svc.devices.UpdatePosture(ctx, tenantID, existing.ID, initialPosture); err != nil {
			return repository.Device{}, err
		}
		dev.Posture = initialPosture
	}

	svc.logAuditErr(svc.appendAudit(ctx, tenantID, in.Actor, "device.mobile_reenrolled", "device", &existing.ID,
		mobileAuditDetails(in.OIDCSubject, in.Platform)))
	return dev, nil
}

// MobilePostureInput is the validated input to ReportMobilePosture.
type MobilePostureInput struct {
	// DeviceKey is the base64 Ed25519 device key from the session
	// token; the device whose posture is updated is resolved from it,
	// so a session can only ever write its OWN device's posture.
	DeviceKey string
	// Posture is the snapshot to persist.
	Posture repository.Posture
	// OIDCSubject / Actor feed the audit trail (see MobileEnrollInput).
	OIDCSubject string
	Actor       *uuid.UUID
}

// ReportMobilePosture validates and persists a posture snapshot for
// the device the calling mobile session is bound to. The device is
// resolved from the session's device key (never a path id), so the
// "a device may only update its own posture" rule is enforced
// structurally — there is no way to address another device. Returns
// ErrNotFound when the device key has not been enrolled yet.
func (svc *Service) ReportMobilePosture(
	ctx context.Context,
	tenantID uuid.UUID,
	in MobilePostureInput,
) (repository.Device, error) {
	if tenantID == uuid.Nil {
		return repository.Device{}, repository.ErrInvalidArgument
	}
	if in.DeviceKey == "" {
		return repository.Device{}, fmt.Errorf("device key is required: %w", repository.ErrInvalidArgument)
	}

	dev, err := svc.devices.GetByPublicKey(ctx, tenantID, in.DeviceKey)
	if err != nil {
		return repository.Device{}, err
	}
	if !dev.Platform.IsMobile() {
		// The session is device-bound to a non-mobile device. This
		// should be unreachable (mobile sessions enrol mobile
		// devices), but guard against it so cross-platform posture
		// signals are validated against a real mobile platform.
		return repository.Device{}, fmt.Errorf("device %s is not a mobile device: %w", dev.ID, repository.ErrInvalidArgument)
	}

	posture, err := validateMobilePosture(in.Posture, dev.Platform, svc.nowFunc())
	if err != nil {
		return repository.Device{}, err
	}
	if err := svc.devices.UpdatePosture(ctx, tenantID, dev.ID, posture); err != nil {
		return repository.Device{}, err
	}
	dev.Posture = posture

	svc.logAuditErr(svc.appendAudit(ctx, tenantID, in.Actor, "device.mobile_posture_reported", "device", &dev.ID,
		mobileAuditDetails(in.OIDCSubject, dev.Platform)))
	return dev, nil
}

// validateMobilePosture enforces platform/signal coherence and
// timestamp sanity, returning a normalised posture.
//
// Coherence: `jailbroken` is an iOS-only signal and `root_detected`
// is Android-only. A snapshot carrying the wrong-platform signal is a
// client bug, so we REJECT it (rather than silently dropping it) to
// surface the bug instead of masking it — a dropped signal could let
// a compromised device look healthy.
//
// Timestamp: an explicit CollectedAt must fall within
// [now-maxPostureAge, now+maxPostureClockSkew]; outside that window it
// is rejected as stale/future. An omitted CollectedAt is stamped with
// the server clock so persisted posture always carries a collection
// time.
func validateMobilePosture(p repository.Posture, platform repository.DevicePlatform, now time.Time) (repository.Posture, error) {
	switch platform {
	case repository.DevicePlatformIOS:
		if p.RootDetected != nil {
			return repository.Posture{}, fmt.Errorf("root_detected is an Android-only signal, not valid for ios: %w", repository.ErrInvalidArgument)
		}
	case repository.DevicePlatformAndroid:
		if p.Jailbroken != nil {
			return repository.Posture{}, fmt.Errorf("jailbroken is an iOS-only signal, not valid for android: %w", repository.ErrInvalidArgument)
		}
	default:
		return repository.Posture{}, fmt.Errorf("platform %q is not a mobile platform: %w", platform, repository.ErrInvalidArgument)
	}

	if p.CollectedAt == nil {
		t := now
		p.CollectedAt = &t
		return p, nil
	}
	collected := p.CollectedAt.UTC()
	if collected.After(now.Add(maxPostureClockSkew)) {
		return repository.Posture{}, fmt.Errorf("collected_at %s is too far in the future: %w", collected.Format(time.RFC3339), repository.ErrInvalidArgument)
	}
	if collected.Before(now.Add(-maxPostureAge)) {
		return repository.Posture{}, fmt.Errorf("collected_at %s is stale (older than %s): %w", collected.Format(time.RFC3339), maxPostureAge, repository.ErrInvalidArgument)
	}
	p.CollectedAt = &collected
	return p, nil
}

// mobileAuditDetails builds the audit details blob recorded for mobile
// device lifecycle events, capturing the OIDC subject (user
// attribution, since devices have no user FK) and the platform. A
// marshal failure (not possible for this fixed string map) degrades to
// an empty object so a logging concern never blocks enrolment.
func mobileAuditDetails(oidcSubject string, platform repository.DevicePlatform) json.RawMessage {
	b, err := json.Marshal(map[string]any{
		"oidc_sub": oidcSubject,
		"platform": string(platform),
		"via":      "mobile_session",
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
