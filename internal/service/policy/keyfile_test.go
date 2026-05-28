package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func newEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func writeFile(t *testing.T, dir, name string, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoadKeySignerFromFile_PEM(t *testing.T) {
	t.Parallel()
	_, priv := newEd25519(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := writeFile(t, t.TempDir(), "key.pem", body, 0o600)

	signer, err := LoadKeySignerFromFile(path)
	if err != nil {
		t.Fatalf("LoadKeySignerFromFile: %v", err)
	}
	if signer.KeyID() == "" {
		t.Fatalf("KeyID should be non-empty for any loaded signer")
	}
	pub := priv.Public().(ed25519.PublicKey)
	if string(signer.PublicKey()) != string(pub) {
		t.Fatalf("PublicKey mismatch")
	}
}

func TestLoadKeySignerFromFile_HexSeed(t *testing.T) {
	t.Parallel()
	_, priv := newEd25519(t)
	seed := priv.Seed()
	path := writeFile(t, t.TempDir(), "key.hex", []byte(hex.EncodeToString(seed)+"\n"), 0o600)

	signer, err := LoadKeySignerFromFile(path)
	if err != nil {
		t.Fatalf("LoadKeySignerFromFile: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if string(signer.PublicKey()) != string(pub) {
		t.Fatalf("PublicKey mismatch — round-trip via hex seed failed")
	}
}

func TestLoadKeySignerFromFile_HexPrivate(t *testing.T) {
	t.Parallel()
	_, priv := newEd25519(t)
	path := writeFile(t, t.TempDir(), "key.hex", []byte(hex.EncodeToString(priv)), 0o600)

	signer, err := LoadKeySignerFromFile(path)
	if err != nil {
		t.Fatalf("LoadKeySignerFromFile: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if string(signer.PublicKey()) != string(pub) {
		t.Fatalf("PublicKey mismatch — round-trip via hex full private failed")
	}
}

func TestLoadKeySignerFromFile_RawSeed(t *testing.T) {
	t.Parallel()
	_, priv := newEd25519(t)
	seed := priv.Seed()
	path := writeFile(t, t.TempDir(), "key.bin", seed, 0o600)

	signer, err := LoadKeySignerFromFile(path)
	if err != nil {
		t.Fatalf("LoadKeySignerFromFile: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if string(signer.PublicKey()) != string(pub) {
		t.Fatalf("PublicKey mismatch — round-trip via raw seed failed")
	}
}

func TestLoadKeySignerFromFile_RejectsWrongPEMType(t *testing.T) {
	t.Parallel()
	body := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("nonsense")})
	path := writeFile(t, t.TempDir(), "key.pem", body, 0o600)
	if _, err := LoadKeySignerFromFile(path); err == nil {
		t.Fatalf("expected error for non-PRIVATE-KEY PEM block")
	}
}

func TestLoadKeySignerFromFile_RejectsWrongLength(t *testing.T) {
	t.Parallel()
	path := writeFile(t, t.TempDir(), "key.bin", make([]byte, 16), 0o600)
	if _, err := LoadKeySignerFromFile(path); err == nil {
		t.Fatalf("expected error for 16-byte input")
	}
}

func TestLoadKeySignerFromFile_RejectsEmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := LoadKeySignerFromFile(""); err == nil {
		t.Fatalf("expected error for empty path")
	}
}

func TestLoadKeySignerFromFile_RejectsMissingFile(t *testing.T) {
	t.Parallel()
	if _, err := LoadKeySignerFromFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestKeySigner_PrepareSigner_OneCallSignsManyTargets(t *testing.T) {
	t.Parallel()
	_, priv := newEd25519(t)
	s := NewKeySigner(priv)
	prepared, err := s.PrepareSigner(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("PrepareSigner: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	for _, msg := range [][]byte{[]byte("a"), []byte("bb"), []byte("ccc"), []byte("dddd")} {
		sig, kid := prepared.Sign(msg)
		if kid != s.KeyID() {
			t.Fatalf("kid mismatch: prepared=%s, signer=%s", kid, s.KeyID())
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("signature verify failed")
		}
	}
}

func TestLoadKeySignerFromFile_RawBytesWithNonHexByte(t *testing.T) {
	t.Parallel()
	// A 64-byte raw private key that contains at least one byte
	// outside the ASCII hex range — looksLikeHex must reject it
	// and the raw-bytes path must accept all 64 bytes verbatim.
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = 0x80 | byte(i)
	}
	dir := t.TempDir()
	p := writeFile(t, dir, "raw64", raw, 0o600)
	ks, err := LoadKeySignerFromFile(p)
	if err != nil {
		t.Fatalf("LoadKeySignerFromFile: %v", err)
	}
	got := []byte(ks.priv)
	if len(got) != ed25519.PrivateKeySize {
		t.Fatalf("expected 64-byte raw private key, got %d bytes", len(got))
	}
	for i := range raw {
		if got[i] != raw[i] {
			t.Fatalf("byte %d mismatch: got 0x%02x want 0x%02x (loader reinterpreted as hex?)", i, got[i], raw[i])
		}
	}
}

func TestLooksLikeHex(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		want bool
	}{
		{"", false},
		{"deadbeef", false},
		{string(make([]byte, 64)), false},
		{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", true},
		{"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", true},
		{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeegg", false},
	}
	for _, c := range cases {
		got := looksLikeHex(c.s)
		if got != c.want {
			t.Errorf("looksLikeHex(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}
