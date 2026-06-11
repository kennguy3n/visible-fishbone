package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// memCredStore is an in-memory DirectoryCredentialStore for vault tests.
// It is deliberately not tenant-isolated (the production RLS layer is
// exercised separately) — these tests cover the seal/unseal + lifecycle
// contract of CredentialVault, not storage scoping.
type memCredStore struct {
	rows map[uuid.UUID][]byte // keyed by configID
}

func newMemCredStore() *memCredStore { return &memCredStore{rows: map[uuid.UUID][]byte{}} }

func (m *memCredStore) GetSealed(_ context.Context, _, configID uuid.UUID) ([]byte, error) {
	sealed, ok := m.rows[configID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return sealed, nil
}

func (m *memCredStore) SetSealed(_ context.Context, _, configID uuid.UUID, sealed []byte) error {
	m.rows[configID] = sealed
	return nil
}

func (m *memCredStore) DeleteSealed(_ context.Context, _, configID uuid.UUID) error {
	if _, ok := m.rows[configID]; !ok {
		return repository.ErrNotFound
	}
	delete(m.rows, configID)
	return nil
}

func newAESGCMSealer(t *testing.T) CredentialSealer {
	t.Helper()
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i + 1)
	}
	w, err := policy.NewAESGCMWrapper(master)
	if err != nil {
		t.Fatalf("NewAESGCMWrapper: %v", err)
	}
	return w
}

func TestCredentialVault_PutResolveRoundTrip(t *testing.T) {
	// Both sealers must round-trip identically from the vault's view.
	sealers := map[string]CredentialSealer{
		"passthrough": policy.PassthroughWrapper{},
		"aesgcm":      newAESGCMSealer(t),
	}
	for name, sealer := range sealers {
		t.Run(name, func(t *testing.T) {
			vault, err := NewCredentialVault(newMemCredStore(), sealer)
			if err != nil {
				t.Fatalf("NewCredentialVault: %v", err)
			}
			tenantID, configID := uuid.New(), uuid.New()
			in := DirectoryCredential{
				BaseURL: "https://acme.okta.com",
				Token:   "ssws-secret-token",
				Subject: "admin@acme.com",
			}
			if err := vault.Put(context.Background(), tenantID, configID, in); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got, err := vault.Resolve(context.Background(), tenantID, repository.IDPConfig{ID: configID})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != in {
				t.Fatalf("round-trip mismatch: got %+v want %+v", got, in)
			}
		})
	}
}

func TestCredentialVault_SealsAtRest(t *testing.T) {
	// With a real AES-GCM sealer the stored bytes must not contain the
	// plaintext token — proving the vault seals before persisting.
	store := newMemCredStore()
	vault, err := NewCredentialVault(store, newAESGCMSealer(t))
	if err != nil {
		t.Fatalf("NewCredentialVault: %v", err)
	}
	tenantID, configID := uuid.New(), uuid.New()
	const secret = "super-secret-directory-token"
	if err := vault.Put(context.Background(), tenantID, configID, DirectoryCredential{
		BaseURL: "https://graph.microsoft.com",
		Token:   secret,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	sealed := store.rows[configID]
	if len(sealed) == 0 {
		t.Fatal("no sealed blob persisted")
	}
	if bytesContains(sealed, []byte(secret)) {
		t.Fatal("sealed blob leaks the plaintext token")
	}
}

func TestCredentialVault_ResolveMissingIsSentinel(t *testing.T) {
	vault, err := NewCredentialVault(newMemCredStore(), policy.PassthroughWrapper{})
	if err != nil {
		t.Fatalf("NewCredentialVault: %v", err)
	}
	_, err = vault.Resolve(context.Background(), uuid.New(), repository.IDPConfig{ID: uuid.New()})
	if !errors.Is(err, ErrNoDirectoryCredential) {
		t.Fatalf("missing credential: got %v want ErrNoDirectoryCredential", err)
	}
}

func TestCredentialVault_PutRejectsEmptyToken(t *testing.T) {
	vault, err := NewCredentialVault(newMemCredStore(), policy.PassthroughWrapper{})
	if err != nil {
		t.Fatalf("NewCredentialVault: %v", err)
	}
	err = vault.Put(context.Background(), uuid.New(), uuid.New(), DirectoryCredential{Token: ""})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("empty token: got %v want ErrInvalidArgument", err)
	}
}

func TestCredentialVault_HasAndClear(t *testing.T) {
	vault, err := NewCredentialVault(newMemCredStore(), policy.PassthroughWrapper{})
	if err != nil {
		t.Fatalf("NewCredentialVault: %v", err)
	}
	tenantID, configID := uuid.New(), uuid.New()

	has, err := vault.Has(context.Background(), tenantID, configID)
	if err != nil || has {
		t.Fatalf("Has before Put: has=%v err=%v want false,nil", has, err)
	}
	if err := vault.Put(context.Background(), tenantID, configID, DirectoryCredential{Token: "tok"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if has, err := vault.Has(context.Background(), tenantID, configID); err != nil || !has {
		t.Fatalf("Has after Put: has=%v err=%v want true,nil", has, err)
	}
	if err := vault.Clear(context.Background(), tenantID, configID); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if has, err := vault.Has(context.Background(), tenantID, configID); err != nil || has {
		t.Fatalf("Has after Clear: has=%v err=%v want false,nil", has, err)
	}
	// Clearing an absent credential is ErrNotFound.
	if err := vault.Clear(context.Background(), tenantID, configID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("Clear absent: got %v want ErrNotFound", err)
	}
}

func TestNewCredentialVault_NilDeps(t *testing.T) {
	if _, err := NewCredentialVault(nil, policy.PassthroughWrapper{}); err == nil {
		t.Fatal("nil store: expected error")
	}
	if _, err := NewCredentialVault(newMemCredStore(), nil); err == nil {
		t.Fatal("nil sealer: expected error")
	}
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
