package iamcore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestGeneratePKCE_ChallengeIsS256OfVerifier(t *testing.T) {
	t.Parallel()
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if p.Method != "S256" {
		t.Errorf("method = %q, want S256", p.Method)
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Errorf("challenge = %q, want S256(verifier) = %q", p.Challenge, want)
	}
	// RFC 7636: verifier length must be 43..128 chars.
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Errorf("verifier length %d out of 43..128", len(p.Verifier))
	}
}

func TestGeneratePKCE_Unique(t *testing.T) {
	t.Parallel()
	a, _ := GeneratePKCE()
	b, _ := GeneratePKCE()
	if a.Verifier == b.Verifier {
		t.Error("two PKCE verifiers must differ")
	}
}

func TestAuthorizeURL_UsesDiscoveryAndSetsPKCEParams(t *testing.T) {
	t.Parallel()
	f := newFakeIAMCore(t)
	defer f.server.Close()
	c := New(f.config())

	raw, err := c.AuthorizeURL(context.Background(), AuthorizeParams{
		RedirectURI:   "https://sng.example.com/callback",
		State:         "state-123",
		Nonce:         "nonce-abc",
		CodeChallenge: "challenge-xyz",
	})
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Endpoint must come from the fake's discovery document.
	if !strings.HasPrefix(raw, f.server.URL+"/oauth2/authorize") {
		t.Errorf("authorize URL = %s, want discovery authorization_endpoint prefix", raw)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "sng-gateway",
		"redirect_uri":          "https://sng.example.com/callback",
		"state":                 "state-123",
		"nonce":                 "nonce-abc",
		"code_challenge":        "challenge-xyz",
		"code_challenge_method": "S256",
		"audience":              "sng-api",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %q = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope %q missing openid", q.Get("scope"))
	}
}

func TestAuthorizeURL_StepUpPromptAndACR(t *testing.T) {
	t.Parallel()
	f := newFakeIAMCore(t)
	defer f.server.Close()
	c := New(f.config())

	raw, err := c.AuthorizeURL(context.Background(), AuthorizeParams{
		RedirectURI:   "https://sng.example.com/callback",
		State:         "s",
		CodeChallenge: "ch",
		Prompt:        "login",
		ACRValues:     "mfa",
	})
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, _ := url.Parse(raw)
	if u.Query().Get("prompt") != "login" {
		t.Errorf("prompt = %q, want login", u.Query().Get("prompt"))
	}
	if u.Query().Get("acr_values") != "mfa" {
		t.Errorf("acr_values = %q, want mfa", u.Query().Get("acr_values"))
	}
}

func TestAuthorizeURL_RequiresStateAndChallenge(t *testing.T) {
	t.Parallel()
	f := newFakeIAMCore(t)
	defer f.server.Close()
	c := New(f.config())

	if _, err := c.AuthorizeURL(context.Background(), AuthorizeParams{
		RedirectURI: "https://sng.example.com/callback", CodeChallenge: "ch",
	}); err == nil {
		t.Error("expected error when state is missing")
	}
	if _, err := c.AuthorizeURL(context.Background(), AuthorizeParams{
		RedirectURI: "https://sng.example.com/callback", State: "s",
	}); err == nil {
		t.Error("expected error when code challenge is missing")
	}
}
