package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ErrNoDirectoryCredential is returned by CredentialVault.Resolve when
// a provider config has no directory credential stored. It is a normal,
// non-fatal condition: an idp_configs row exists for mobile native-SSO
// token validation, but the operator has not opted that provider into
// directory sync. The SyncService treats it as "skip this provider",
// not an error, so an enabled OIDC config never forces a credential.
var ErrNoDirectoryCredential = errors.New("identity: no directory credential configured")

// DirectoryCredentialStore is the persistence seam for sealed directory
// credentials, keyed by the owning idp_configs row. Implementations
// MUST scope every operation to tenantID so one tenant can neither read
// nor overwrite another's credential. The bytes crossing this interface
// are already sealed (see CredentialVault): the store never sees
// plaintext.
type DirectoryCredentialStore interface {
	// GetSealed returns the sealed blob for a config, or
	// repository.ErrNotFound when none is stored.
	GetSealed(ctx context.Context, tenantID, configID uuid.UUID) ([]byte, error)
	// SetSealed upserts the sealed blob for a config (one row per
	// config). Returns repository.ErrNotFound when the config does not
	// exist within the tenant.
	SetSealed(ctx context.Context, tenantID, configID uuid.UUID, sealed []byte) error
	// DeleteSealed removes a config's credential. Returns
	// repository.ErrNotFound when none is stored.
	DeleteSealed(ctx context.Context, tenantID, configID uuid.UUID) error
}

// CredentialSealer is the at-rest encryption seam. Its method set is
// the same Wrap/Unwrap contract as policy.PrivateKeyWrapper, so the
// platform's existing policy.AESGCMWrapper (AES-256-GCM under the
// operator master key, tenant UUID as AAD) and policy.PassthroughWrapper
// (dev / Postgres-TDE) both satisfy it directly — no new crypto. The
// tenant UUID is bound as additional-authenticated-data, so a blob
// sealed for one tenant cannot be unsealed under another even with the
// same master key.
type CredentialSealer interface {
	Wrap(ctx context.Context, tenantID uuid.UUID, plaintext []byte) ([]byte, error)
	Unwrap(ctx context.Context, tenantID uuid.UUID, sealed []byte) ([]byte, error)
}

// sealedCredential is the stable on-disk JSON shape sealed into the
// store. It is intentionally separate from DirectoryCredential (which
// has no serialization tags) so the wire format is explicit and
// independent of in-memory field layout.
type sealedCredential struct {
	BaseURL string `json:"base_url,omitempty"`
	Token   string `json:"token"`
	Subject string `json:"subject,omitempty"`
}

// CredentialVault is the production CredentialResolver: it seals
// operator-supplied directory credentials at rest and unseals them for
// the SyncService. It also serves the admin write side (Put / Clear) so
// the seal/unseal logic lives in exactly one place.
type CredentialVault struct {
	store  DirectoryCredentialStore
	sealer CredentialSealer
}

// NewCredentialVault wires the vault. Both dependencies are required;
// passing a nil store or sealer is a programming error.
func NewCredentialVault(store DirectoryCredentialStore, sealer CredentialSealer) (*CredentialVault, error) {
	if store == nil {
		return nil, errors.New("identity: nil directory credential store")
	}
	if sealer == nil {
		return nil, errors.New("identity: nil credential sealer")
	}
	return &CredentialVault{store: store, sealer: sealer}, nil
}

// Put seals cred and stores it for the given config. The token is
// required — a credential with no bearer token is useless (the
// directory client factory rejects it), so an empty token is a bad
// request rather than a silently-stored no-op.
func (v *CredentialVault) Put(ctx context.Context, tenantID, configID uuid.UUID, cred DirectoryCredential) error {
	if tenantID == uuid.Nil || configID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	if cred.Token == "" {
		return fmt.Errorf("%w: directory credential token is required", repository.ErrInvalidArgument)
	}
	// Copy fields explicitly rather than converting cred to
	// sealedCredential: the two types are intentionally decoupled (see
	// the sealedCredential doc) so the on-disk wire format stays
	// independent of the in-memory layout.
	plaintext, err := json.Marshal(sealedCredential{ //nolint:staticcheck // S1016: explicit copy is intentional; sealedCredential is decoupled from DirectoryCredential by design
		BaseURL: cred.BaseURL,
		Token:   cred.Token,
		Subject: cred.Subject,
	})
	if err != nil {
		return fmt.Errorf("marshal directory credential: %w", err)
	}
	sealed, err := v.sealer.Wrap(ctx, tenantID, plaintext)
	if err != nil {
		return fmt.Errorf("seal directory credential: %w", err)
	}
	return v.store.SetSealed(ctx, tenantID, configID, sealed)
}

// Has reports whether a config has a directory credential stored,
// without unsealing it. Used by the admin surface to show whether a
// provider is opted into directory sync.
func (v *CredentialVault) Has(ctx context.Context, tenantID, configID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || configID == uuid.Nil {
		return false, repository.ErrInvalidArgument
	}
	_, err := v.store.GetSealed(ctx, tenantID, configID)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Clear removes a config's directory credential. Returns
// repository.ErrNotFound when none was stored.
func (v *CredentialVault) Clear(ctx context.Context, tenantID, configID uuid.UUID) error {
	if tenantID == uuid.Nil || configID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return v.store.DeleteSealed(ctx, tenantID, configID)
}

// Resolve implements CredentialResolver. It fetches and unseals the
// credential for cfg. A missing credential is surfaced as
// ErrNoDirectoryCredential (not a hard error) so the sync loop can skip
// providers that aren't opted into directory sync.
func (v *CredentialVault) Resolve(ctx context.Context, tenantID uuid.UUID, cfg repository.IDPConfig) (DirectoryCredential, error) {
	sealed, err := v.store.GetSealed(ctx, tenantID, cfg.ID)
	if errors.Is(err, repository.ErrNotFound) {
		return DirectoryCredential{}, ErrNoDirectoryCredential
	}
	if err != nil {
		return DirectoryCredential{}, fmt.Errorf("load directory credential: %w", err)
	}
	plaintext, err := v.sealer.Unwrap(ctx, tenantID, sealed)
	if err != nil {
		return DirectoryCredential{}, fmt.Errorf("unseal directory credential: %w", err)
	}
	var sc sealedCredential
	if err := json.Unmarshal(plaintext, &sc); err != nil {
		return DirectoryCredential{}, fmt.Errorf("decode directory credential: %w", err)
	}
	// Copy fields explicitly rather than converting sc to
	// DirectoryCredential: see the sealedCredential doc for why the two
	// types are kept decoupled.
	return DirectoryCredential{ //nolint:staticcheck // S1016: explicit copy is intentional; sealedCredential is decoupled from DirectoryCredential by design
		BaseURL: sc.BaseURL,
		Token:   sc.Token,
		Subject: sc.Subject,
	}, nil
}

// Ensure CredentialVault satisfies the resolver contract the
// SyncService consumes.
var _ CredentialResolver = (*CredentialVault)(nil)
