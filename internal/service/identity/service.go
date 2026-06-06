// Package identity implements device enrollment and lifecycle
// management. The core flow is:
//
//  1. GenerateClaimToken — an admin creates a one-time token. The
//     plaintext is returned exactly once; only the SHA-256 hash is
//     persisted.
//  2. RedeemClaimToken — a device presents the plaintext, the
//     service verifies it via hash comparison, marks it redeemed,
//     and creates the device record with the provided Ed25519
//     public key + platform.
//  3. Heartbeat / PostureUpdate — the device periodically pings
//     and submits its posture snapshot.
//
// Every mutation is audit-logged.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultTokenTTL is the claim-token lifetime when the caller does
// not supply one. 24 hours matches the sn360-security-platform
// default.
const DefaultTokenTTL = 24 * time.Hour

// Service implements identity + enrollment operations.
type Service struct {
	devices  repository.DeviceRepository
	tokens   repository.ClaimTokenRepository
	audit    repository.AuditLogRepository
	bindings repository.DeviceIdentityBindingRepository
	logger   *slog.Logger
	nowFunc  func() time.Time
}

// Option configures optional Service behaviour without breaking the
// base constructor signature used across the codebase.
type Option func(*Service)

// WithDeviceIdentityBindings enables binding enrolled devices to their
// upstream iam-core user (Session 2A, migration 044). When set, an
// enrollment performed by an iam-core-authenticated caller records the
// (iam_core_user_id, device_id, ed25519_public_key) mapping.
func WithDeviceIdentityBindings(bindings repository.DeviceIdentityBindingRepository) Option {
	return func(s *Service) {
		if bindings != nil {
			s.bindings = bindings
		}
	}
}

// New returns a ready-to-use identity service.
func New(
	devices repository.DeviceRepository,
	tokens repository.ClaimTokenRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
	opts ...Option,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		devices: devices,
		tokens:  tokens,
		audit:   audit,
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GenerateClaimTokenResult holds both the persisted token record
// and the plaintext. The plaintext is returned exactly once.
type GenerateClaimTokenResult struct {
	Token     repository.ClaimToken
	Plaintext string
}

// GenerateClaimToken creates a one-time enrollment credential.
// Returns the plaintext (base64url-encoded) for delivery to the
// device operator + the persisted hash record.
func (svc *Service) GenerateClaimToken(
	ctx context.Context,
	tenantID uuid.UUID,
	ttl time.Duration,
	createdBy *uuid.UUID,
) (GenerateClaimTokenResult, error) {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return GenerateClaimTokenResult{}, fmt.Errorf("generate random: %w", err)
	}
	hash := sha256.Sum256(secret)
	plaintext := base64.RawURLEncoding.EncodeToString(secret)

	now := svc.nowFunc()
	ct := repository.ClaimToken{
		TokenHash: hash[:],
		ExpiresAt: now.Add(ttl),
		CreatedBy: createdBy,
	}

	saved, err := svc.tokens.Create(ctx, tenantID, ct)
	if err != nil {
		return GenerateClaimTokenResult{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, createdBy, "claim_token.created", "claim_token", &saved.ID, nil))
	return GenerateClaimTokenResult{Token: saved, Plaintext: plaintext}, nil
}

// RedeemClaimToken verifies the plaintext token, marks it redeemed,
// and creates the device record. If device creation fails after the
// token was redeemed, the token is un-redeemed via UnredeemByHash
// so the enrollment can be retried with the same credential.
// Returns the newly enrolled device.
func (svc *Service) RedeemClaimToken(
	ctx context.Context,
	tenantID uuid.UUID,
	plaintextToken string,
	deviceName string,
	platform repository.DevicePlatform,
	publicKey string,
	posture repository.Posture,
) (repository.Device, error) {
	raw, err := base64.RawURLEncoding.DecodeString(plaintextToken)
	if err != nil {
		return repository.Device{}, fmt.Errorf("invalid claim token encoding: %w", repository.ErrInvalidArgument)
	}
	hash := sha256.Sum256(raw)
	now := svc.nowFunc()

	if _, err := svc.tokens.Redeem(ctx, tenantID, hash[:], now); err != nil {
		return repository.Device{}, err
	}

	dev, err := svc.devices.Create(ctx, tenantID, repository.Device{
		Name:             deviceName,
		Platform:         platform,
		PublicKeyEd25519: publicKey,
		Posture:          posture,
	})
	if err != nil {
		// Compensating action: un-redeem the token so the
		// enrollment can be retried. Best-effort — if
		// UnredeemByHash itself fails (e.g. DB down), we log
		// the failure but return the original device-create
		// error to the caller.
		if unErr := svc.tokens.UnredeemByHash(ctx, tenantID, hash[:]); unErr != nil {
			svc.logger.Error("identity: failed to un-redeem token after device creation failure",
				slog.Any("unredeemError", unErr),
				slog.Any("deviceCreateError", err))
		}
		return repository.Device{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, nil, "device.enrolled", "device", &dev.ID, nil))
	// Session 2A: if the enrolling caller is authenticated via
	// iam-core, bind the freshly enrolled device to that iam-core
	// user. Binding failures must not fail the enrollment (the device
	// is already created + audited); they are logged for reconciliation.
	if err := svc.bindEnrolledDevice(ctx, tenantID, dev); err != nil {
		svc.logger.Error("identity: failed to bind device to iam-core identity",
			slog.String("deviceID", dev.ID.String()),
			slog.Any("error", err))
	}
	return dev, nil
}

// bindEnrolledDevice records the device ↔ iam-core user mapping when
// the bindings repo is configured AND the request context carries an
// iam-core identity. It is a no-op otherwise (legacy API-key / mobile
// / HMAC enrollments are unaffected).
func (svc *Service) bindEnrolledDevice(ctx context.Context, tenantID uuid.UUID, dev repository.Device) error {
	if svc.bindings == nil {
		return nil
	}
	ident, ok := middleware.IAMCoreIdentityFromContext(ctx)
	if !ok || ident.Subject == "" {
		return nil
	}
	return svc.BindDeviceIdentity(ctx, tenantID, ident.Subject, dev.ID, dev.PublicKeyEd25519)
}

// BindDeviceIdentity records (or updates) the binding between a device
// and an iam-core user. Exposed for callers that enroll devices
// outside RedeemClaimToken (e.g. mobile self-enrollment) and want to
// attach the upstream identity explicitly. Returns nil when the
// bindings repository is not configured.
func (svc *Service) BindDeviceIdentity(ctx context.Context, tenantID uuid.UUID, iamCoreUserID string, deviceID uuid.UUID, ed25519PublicKey string) error {
	if svc.bindings == nil {
		return nil
	}
	if iamCoreUserID == "" || deviceID == uuid.Nil {
		return fmt.Errorf("iam-core user id and device id are required: %w", repository.ErrInvalidArgument)
	}
	b, err := svc.bindings.Upsert(ctx, tenantID, repository.DeviceIdentityBinding{
		DeviceID:         deviceID,
		IAMCoreUserID:    iamCoreUserID,
		Ed25519PublicKey: ed25519PublicKey,
	})
	if err != nil {
		return err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, nil, "device.identity_bound", "device", &b.DeviceID, nil))
	return nil
}

// Heartbeat updates the device's last-seen timestamp.
func (svc *Service) Heartbeat(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	return svc.devices.UpdateLastSeen(ctx, tenantID, deviceID, svc.nowFunc())
}

// UpdatePosture stores a new posture snapshot for the device.
func (svc *Service) UpdatePosture(ctx context.Context, tenantID, deviceID uuid.UUID, p repository.Posture) error {
	return svc.devices.UpdatePosture(ctx, tenantID, deviceID, p)
}

func (svc *Service) appendAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details json.RawMessage,
) error {
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	// Stamp acting API-key ID into details for machine-to-machine
	// authenticated requests; see middleware.EnrichAuditDetails for
	// the rationale (actor_id is a *user* UUID and NULL on API-key
	// paths, so machine-actor attribution lives in details).
	details = middleware.EnrichAuditDetails(ctx, details)
	_, err := svc.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

func (svc *Service) logAuditErr(err error) {
	if err != nil {
		svc.logger.Warn("identity: audit append failed", slog.Any("error", err))
	}
}
