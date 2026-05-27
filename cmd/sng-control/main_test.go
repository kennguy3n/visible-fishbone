package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

func TestRedactURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"nats://127.0.0.1:4222", "nats://127.0.0.1:4222"},
		{"tls://nats.example.com:4222", "tls://nats.example.com:4222"},
		{"nats://user:hunter2@host:4222", "nats://user:xxxxx@host:4222"},
		{"nats://user@host:4222", "nats://user@host:4222"},
		{"nats://:token@host:4222", "nats://:xxxxx@host:4222"},
	}
	for _, c := range cases {
		got := redactURL(c.in)
		if got != c.want {
			t.Errorf("redactURL(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.Contains(got, "hunter2") || strings.Contains(got, "token") && c.want != got {
			t.Errorf("redactURL(%q) leaked secret: %q", c.in, got)
		}
	}
}

func TestBuildNATSTLSOptions_Empty(t *testing.T) {
	opts, err := buildNATSTLSOptions(&config.NATS{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("expected no TLS options for empty config, got %d", len(opts))
	}
}

func TestBuildNATSTLSOptions_HalfMTLS(t *testing.T) {
	_, err := buildNATSTLSOptions(&config.NATS{TLSCertFile: "cert.pem"})
	if err == nil {
		t.Fatal("expected error when only TLSCertFile is set without TLSKeyFile")
	}
	_, err = buildNATSTLSOptions(&config.NATS{TLSKeyFile: "key.pem"})
	if err == nil {
		t.Fatal("expected error when only TLSKeyFile is set without TLSCertFile")
	}
}

func TestBuildNATSTLSOptions_MissingCAFile(t *testing.T) {
	_, err := buildNATSTLSOptions(&config.NATS{TLSCAFile: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("expected error when CA file is missing")
	}
}

func TestBuildNATSTLSOptions_GoodCA(t *testing.T) {
	caPath := writeTempCA(t)
	opts, err := buildNATSTLSOptions(&config.NATS{TLSCAFile: caPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) == 0 {
		t.Error("expected at least one TLS option")
	}
}

func TestBuildNATSTLSOptions_InsecureFlag(t *testing.T) {
	opts, err := buildNATSTLSOptions(&config.NATS{TLSInsecure: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts) == 0 {
		t.Error("expected at least one TLS option when TLSInsecure is set")
	}
}

func TestBuildNATSTLSOptions_BadCAContent(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bogus, []byte("not a PEM file"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildNATSTLSOptions(&config.NATS{TLSCAFile: bogus})
	if err == nil {
		t.Fatal("expected error when CA file does not contain valid PEM")
	}
}

// writeTempCA generates a throwaway self-signed cert in PEM format
// and returns its path, used to exercise the CA parsing path.
func writeTempCA(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "ca.pem")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]string{
		"debug":   "DEBUG",
		"info":    "INFO",
		"warn":    "WARN",
		"warning": "WARN",
		"error":   "ERROR",
		"":        "INFO",
		"GARBAGE": "INFO",
	}
	for in, want := range cases {
		got := parseLogLevel(in).String()
		if got != want {
			t.Errorf("parseLogLevel(%q) = %s, want %s", in, got, want)
		}
	}
}
