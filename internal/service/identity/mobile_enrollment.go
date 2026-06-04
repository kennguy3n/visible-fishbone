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
// the repository (the partial unique index in migration 037); we
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
				// Surface the real lookup failure (e.g. a transient DB
				// error), not the original ErrConflict — returning the
				// latter would mislead the client into a 409 and an
				// incorrect retry decision.
				return MobileEnrollResult{}, gerr
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
	// Admin controls are authoritative over a stateless session JWT: a
	// device an admin has suspended or soft-deleted must NOT be
	// silently reinstated by a re-enrolment from a still-valid session.
	// Refuse with 403 so suspend/delete is an effective kill-switch for
	// the self-service surface; reinstatement must go through the
	// admin device-status path.
	if disabled, reason := mobileDeviceDisabled(existing.Status); disabled {
		return repository.Device{}, fmt.Errorf(
			"device has been administratively %s and cannot be re-enrolled via self-service: %w",
			reason, repository.ErrForbidden)
	}

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
	// Re-activate a pending device (or one that never had its enrolment
	// timestamp stamped). Suspended/deleted devices were already
	// rejected above, so the only non-active status reaching here is
	// pending. Use a conditional TransitionStatus(from: observed status)
	// rather than an unconditional UpdateStatus: it closes the TOCTOU
	// window where an admin suspends/deletes the device between the
	// mobileDeviceDisabled check above and this write — without the
	// precondition the write would silently clobber that suspend and
	// reinstate the device. A lost CAS surfaces as ErrForbidden, which
	// is exactly the "device was just disabled" answer the caller wants.
	if existing.Status != repository.DeviceStatusActive || existing.EnrolledAt == nil {
		updated, err := svc.devices.TransitionStatus(ctx, tenantID, existing.ID, existing.Status, repository.DeviceStatusActive)
		if err != nil {
			return repository.Device{}, err
		}
		dev = updated
	}

	if in.Posture != nil {
		if err := svc.devices.UpdatePosture(ctx, tenantID, existing.ID, initialPosture); err != nil {
			return repository.Device{}, err
		}
		// Re-read so the returned device reflects DB-persisted state,
		// in particular the updated_at advanced by the
		// devices_set_updated_at trigger (and by the memory store).
		// Patching only dev.Posture would leave a stale updated_at.
		refreshed, err := svc.devices.Get(ctx, tenantID, existing.ID)
		if err != nil {
			return repository.Device{}, err
		}
		dev = refreshed
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
	// Same kill-switch as enrolment: an administratively suspended or
	// soft-deleted device may not keep its posture fresh off a
	// still-valid session JWT, since stale-but-"healthy" posture could
	// let a disabled device retain ZTNA access until the token expires.
	if disabled, reason := mobileDeviceDisabled(dev.Status); disabled {
		return repository.Device{}, fmt.Errorf(
			"device has been administratively %s and cannot report posture: %w",
			reason, repository.ErrForbidden)
	}

	// Capture the clock once so posture validation and the liveness
	// stamp below share a single instant (mirrors EnrollMobileDevice).
	// Two separate nowFunc() calls would drift apart under a
	// deterministic test clock that advances on every call.
	now := svc.nowFunc()
	posture, err := validateMobilePosture(in.Posture, dev.Platform, now)
	if err != nil {
		return repository.Device{}, err
	}
	if err := svc.devices.UpdatePosture(ctx, tenantID, dev.ID, posture); err != nil {
		return repository.Device{}, err
	}
	// A posture report is also proof-of-liveness: the device made a
	// fresh, authenticated round-trip to the control plane. The desktop
	// path advances last_seen_at via an explicit Heartbeat; mobile has
	// no separate heartbeat, so fold liveness into the posture report.
	// Without this, a device actively reporting healthy posture would
	// still show as stale/offline in monitoring that filters on
	// last_seen_at.
	if err := svc.devices.UpdateLastSeen(ctx, tenantID, dev.ID, now); err != nil {
		return repository.Device{}, err
	}
	// Re-read so the returned device carries the freshly persisted
	// state — the posture, the updated_at advanced by the
	// devices_set_updated_at trigger (and by the memory store), and the
	// last_seen_at just stamped above. Patching only dev.Posture would
	// echo a stale updated_at/last_seen_at and break client cache/ETag
	// comparisons.
	refreshed, err := svc.devices.Get(ctx, tenantID, dev.ID)
	if err != nil {
		return repository.Device{}, err
	}
	dev = refreshed

	svc.logAuditErr(svc.appendAudit(ctx, tenantID, in.Actor, "device.mobile_posture_reported", "device", &dev.ID,
		mobileAuditDetails(in.OIDCSubject, dev.Platform)))
	return dev, nil
}

// mobileDeviceDisabled reports whether a device has been
// administratively disabled (suspended or soft-deleted) and therefore
// must not be acted on by the mobile self-service endpoints. The
// session JWT is stateless (it only expires), so device status is the
// authoritative live control: gating both enrolment and posture
// reporting on it makes admin suspend/delete an effective kill-switch
// for the self-service surface even while a token remains unexpired.
// The returned reason is the offending status, for the error message.
func mobileDeviceDisabled(status repository.DeviceStatus) (bool, repository.DeviceStatus) {
	switch status {
	case repository.DeviceStatusSuspended, repository.DeviceStatusDeleted:
		return true, status
	default:
		return false, status
	}
}

// MobileDeviceRevoked reports whether a mobile session bound to
// deviceKey under tenantID must be refused because the device it is
// bound to has been administratively disabled. It is the live-status
// check behind the auth-middleware kill-switch
// (handler.NewMobileDeviceStatusResolver adapts it to
// middleware.MobileDeviceStatusResolver), extending the suspend/delete
// control from just the self-service endpoints to every endpoint a
// mobile token can reach.
//
// Returns (true, nil) when the device exists but has been suspended or
// soft-deleted. Returns (false, nil) when the device is active OR not
// yet enrolled: suspend/delete are soft transitions that leave the row
// in place (see UpdateStatus), so a disabled device is always resolved
// and caught by status — an ErrNotFound therefore means "no device for
// this key yet", which is precisely the state of a valid session
// calling the enrolment endpoint for the first time. Treating that as
// revoked would 403 first-time enrolment in the middleware before the
// request ever reached the handler, so a not-yet-enrolled key must be
// allowed through (the enrolment endpoint then creates the device).
// Returns (false, err) on an infrastructure failure so the caller can
// apply its fail-open/closed policy; a partially-identified session
// (missing tenant or key) is left to the endpoint's own validation.
func (svc *Service) MobileDeviceRevoked(ctx context.Context, tenantID uuid.UUID, deviceKey string) (bool, error) {
	if tenantID == uuid.Nil || deviceKey == "" {
		return false, nil
	}
	dev, err := svc.devices.GetByPublicKey(ctx, tenantID, deviceKey)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	disabled, _ := mobileDeviceDisabled(dev.Status)
	return disabled, nil
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

	// Desktop/general signals have no meaning on ios/android (the
	// mobile equivalents are passcode_set / biometric_ready /
	// mdm_enrolled) and are intentionally absent from the OpenAPI
	// MobilePosture schema. Reject them rather than silently
	// persisting an incoherent snapshot — fail-closed, consistent with
	// the cross-platform mobile-signal rejection above. (DecodeJSON's
	// DisallowUnknownFields cannot catch these: they are real Go fields
	// on the shared Posture struct, so the strictness must live here.)
	switch {
	case p.DiskEncrypted != nil:
		return repository.Posture{}, fmt.Errorf("disk_encrypted is a desktop-only signal, not valid for %s: %w", platform, repository.ErrInvalidArgument)
	case p.FirewallEnabled != nil:
		return repository.Posture{}, fmt.Errorf("firewall_enabled is a desktop-only signal, not valid for %s: %w", platform, repository.ErrInvalidArgument)
	case p.ScreenLock != nil:
		return repository.Posture{}, fmt.Errorf("screen_lock is a desktop-only signal, not valid for %s: %w", platform, repository.ErrInvalidArgument)
	case p.PatchLevel != "":
		return repository.Posture{}, fmt.Errorf("patch_level is a desktop-only signal, not valid for %s: %w", platform, repository.ErrInvalidArgument)
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
