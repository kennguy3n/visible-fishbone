package policy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func newMaster(t *testing.T) []byte {
	t.Helper()
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return m
}

func TestAESGCMWrapper_RoundTrip(t *testing.T) {
	t.Parallel()
	w, err := NewAESGCMWrapper(newMaster(t))
	if err != nil {
		t.Fatalf("NewAESGCMWrapper: %v", err)
	}
	tenant := uuid.New()
	seed := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	wrapped, err := w.Wrap(context.Background(), tenant, seed)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(wrapped) != 12+len(seed)+16 {
		t.Fatalf("expected nonce(12)+ct+tag(16); got %d bytes (seed=%d)", len(wrapped), len(seed))
	}
	out, err := w.Unwrap(context.Background(), tenant, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(out) != string(seed) {
		t.Fatalf("round-trip mismatch: got %x want %x", out, seed)
	}
}

func TestAESGCMWrapper_RejectsWrongTenant(t *testing.T) {
	t.Parallel()
	w, err := NewAESGCMWrapper(newMaster(t))
	if err != nil {
		t.Fatalf("NewAESGCMWrapper: %v", err)
	}
	a := uuid.New()
	b := uuid.New()
	wrapped, err := w.Wrap(context.Background(), a, []byte("hello world"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w.Unwrap(context.Background(), b, wrapped); !errors.Is(err, ErrAESGCMUnwrap) {
		t.Fatalf("expected ErrAESGCMUnwrap on tenant mismatch, got %v", err)
	}
}

func TestAESGCMWrapper_RejectsWrongMaster(t *testing.T) {
	t.Parallel()
	w1, err := NewAESGCMWrapper(newMaster(t))
	if err != nil {
		t.Fatalf("w1: %v", err)
	}
	w2, err := NewAESGCMWrapper(newMaster(t))
	if err != nil {
		t.Fatalf("w2: %v", err)
	}
	tenant := uuid.New()
	wrapped, err := w1.Wrap(context.Background(), tenant, []byte("hello world"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w2.Unwrap(context.Background(), tenant, wrapped); !errors.Is(err, ErrAESGCMUnwrap) {
		t.Fatalf("expected ErrAESGCMUnwrap on master mismatch, got %v", err)
	}
}

func TestAESGCMWrapper_RejectsTamperedCiphertext(t *testing.T) {
	t.Parallel()
	w, err := NewAESGCMWrapper(newMaster(t))
	if err != nil {
		t.Fatalf("NewAESGCMWrapper: %v", err)
	}
	tenant := uuid.New()
	wrapped, err := w.Wrap(context.Background(), tenant, []byte("hello world"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// Flip a bit in the ciphertext (past the nonce).
	wrapped[15] ^= 0x01
	if _, err := w.Unwrap(context.Background(), tenant, wrapped); !errors.Is(err, ErrAESGCMUnwrap) {
		t.Fatalf("expected ErrAESGCMUnwrap on tampered ciphertext, got %v", err)
	}
}

func TestAESGCMWrapper_RejectsShortInput(t *testing.T) {
	t.Parallel()
	w, err := NewAESGCMWrapper(newMaster(t))
	if err != nil {
		t.Fatalf("NewAESGCMWrapper: %v", err)
	}
	for _, n := range []int{0, 1, 11, 12, 27} {
		if _, err := w.Unwrap(context.Background(), uuid.New(), make([]byte, n)); !errors.Is(err, ErrAESGCMUnwrap) {
			t.Fatalf("expected ErrAESGCMUnwrap for input of %d bytes, got %v", n, err)
		}
	}
}

func TestNewAESGCMWrapper_RejectsBadMasterLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewAESGCMWrapper(make([]byte, n)); err == nil {
			t.Fatalf("expected error for master of %d bytes, got nil", n)
		}
	}
}

func TestLoadAESGCMMasterFromEnv_FromBase64(t *testing.T) {
	master := newMaster(t)
	t.Setenv("POLICY_KEY_WRAP_MASTER_B64", base64.StdEncoding.EncodeToString(master))
	t.Setenv("POLICY_KEY_WRAP_MASTER_FILE", "")
	got, err := LoadAESGCMMasterFromEnv()
	if err != nil {
		t.Fatalf("LoadAESGCMMasterFromEnv: %v", err)
	}
	if string(got) != string(master) {
		t.Fatalf("round-trip via base64 env failed")
	}
}

func TestLoadAESGCMMasterFromEnv_FromFile_Raw(t *testing.T) {
	master := newMaster(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "master.bin")
	if err := os.WriteFile(path, master, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("POLICY_KEY_WRAP_MASTER_B64", "")
	t.Setenv("POLICY_KEY_WRAP_MASTER_FILE", path)
	got, err := LoadAESGCMMasterFromEnv()
	if err != nil {
		t.Fatalf("LoadAESGCMMasterFromEnv: %v", err)
	}
	if string(got) != string(master) {
		t.Fatalf("round-trip via raw file failed")
	}
}

func TestLoadAESGCMMasterFromEnv_FromFile_Base64WithTrailingNewline(t *testing.T) {
	master := newMaster(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "master.b64")
	body := base64.StdEncoding.EncodeToString(master) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("POLICY_KEY_WRAP_MASTER_B64", "")
	t.Setenv("POLICY_KEY_WRAP_MASTER_FILE", path)
	got, err := LoadAESGCMMasterFromEnv()
	if err != nil {
		t.Fatalf("LoadAESGCMMasterFromEnv: %v", err)
	}
	if string(got) != string(master) {
		t.Fatalf("round-trip via base64 file failed")
	}
}

func TestLoadAESGCMMasterFromEnv_NoEnvReturnsNil(t *testing.T) {
	t.Setenv("POLICY_KEY_WRAP_MASTER_B64", "")
	t.Setenv("POLICY_KEY_WRAP_MASTER_FILE", "")
	got, err := LoadAESGCMMasterFromEnv()
	if err != nil {
		t.Fatalf("LoadAESGCMMasterFromEnv: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil when no env set, got %d bytes", len(got))
	}
}

func TestLoadAESGCMMasterFromEnv_RejectsBadBase64(t *testing.T) {
	t.Setenv("POLICY_KEY_WRAP_MASTER_B64", "not-base64-!")
	t.Setenv("POLICY_KEY_WRAP_MASTER_FILE", "")
	if _, err := LoadAESGCMMasterFromEnv(); err == nil {
		t.Fatalf("expected error for invalid base64")
	}
}

func TestLoadAESGCMMasterFromEnv_RejectsWrongLength(t *testing.T) {
	t.Setenv("POLICY_KEY_WRAP_MASTER_B64", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	t.Setenv("POLICY_KEY_WRAP_MASTER_FILE", "")
	if _, err := LoadAESGCMMasterFromEnv(); err == nil {
		t.Fatalf("expected error for 16-byte master via base64")
	}
}
