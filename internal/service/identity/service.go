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
	devices repository.DeviceRepository
	tokens  repository.ClaimTokenRepository
	audit   repository.AuditLogRepository
	logger  *slog.Logger
	nowFunc func() time.Time
}

// New returns a ready-to-use identity service.
func New(
	devices repository.DeviceRepository,
	tokens repository.ClaimTokenRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		devices: devices,
		tokens:  tokens,
		audit:   audit,
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
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
	return dev, nil
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
