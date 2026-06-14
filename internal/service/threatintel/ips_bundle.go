package threatintel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

// IPSRuleSchemaVersion is the schema version stamped into the
// IpsRuleBundleClaims body. It matches the edge's expected `v` field
// (1 today). Bump only on a breaking body-layout change.
const IPSRuleSchemaVersion = 1

// DefaultIPSRuleSubject is the NATS subject the signed IPS rule
// bundle is published on. Like the DNS feed bundle it rides the
// policy stream under the platform pseudo-tenant (the rules are
// platform-global threat intelligence, not tenant data) but on a
// distinct, versioned subject so the edge's IPS consumer subscribes
// independently of the DNS consumer.
const DefaultIPSRuleSubject = "sng.platform.policy.ips.rules.v1"

// IPS rule source identifiers. Wire-identical to the edge's
// sng_ips::rules::RuleSource serde ids (snake_case). The threat-intel
// producer is operator/control-plane authored, so it stamps
// CustomOrg.
const (
	IPSRuleSourceEmergingThreats = "emerging_threats"
	IPSRuleSourceSuricataUpdate  = "suricata_update"
	IPSRuleSourceCustomOrg       = "custom_org"
)

// IPSRuleBundleClaims is the signable body of an IPS rule bundle. The
// MessagePack encoding (named map via msgpack field tags) is
// wire-compatible with the edge's sng_ips::rules::IpsRuleBundleClaims
// (`#[serde(rename = ...)]`): the Rust verifier decodes these exact
// bytes through IpsRuleBundleClaims::from_body after verifying the
// signature over them.
type IPSRuleBundleClaims struct {
	// SchemaVersion is the body layout version (see
	// IPSRuleSchemaVersion). Edge field `v`.
	SchemaVersion uint8 `msgpack:"v"`
	// Version is a monotonically increasing revision. The edge
	// verifier rejects any bundle whose version is <= the installed
	// one, so an out-of-order or replayed delivery cannot roll the
	// rule set back. Edge field `rev`.
	Version uint64 `msgpack:"rev"`
	// Compiler is a free-form producer identifier, surfaced on
	// telemetry only. Edge field `comp`.
	Compiler string `msgpack:"comp"`
	// RulesText is the inline, line-separated Suricata rule set.
	// Edge field `rules`.
	RulesText string `msgpack:"rules"`
	// Source is the provenance of the rules (telemetry / stats only;
	// the signature covers the body regardless). Edge field `src`.
	Source string `msgpack:"src"`
}

// EncodeBody returns the canonical MessagePack bytes of the claims —
// the exact bytes signed by the producer and verified+decoded on the
// edge. msgpack.Marshal emits a named map (one key per msgpack tag),
// which is what the edge's rmp_serde::from_slice expects.
func (c IPSRuleBundleClaims) EncodeBody() ([]byte, error) {
	out, err := msgpack.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("threatintel: marshal ips rule bundle body: %w", err)
	}
	return out, nil
}

// SignedIPSRuleBundle is the self-describing wire envelope for a
// signed IPS rule bundle. Body is the base64 (std) MessagePack
// IPSRuleBundleClaims; Signature is the base64 Ed25519 signature over
// the DECODED body bytes; SigningKeyID is the edge trust-store key id
// (16 lowercase hex chars, the 8-byte public-key prefix) the consumer
// selects its pinned verifying key by; PublicKey is advisory.
//
// The envelope is JSON+base64 for inspectability and to mirror the
// DNS SignedBundle; the security-relevant bytes (Body) are the
// MessagePack body the edge verifier consumes verbatim.
type SignedIPSRuleBundle struct {
	Algorithm    string `json:"alg"`
	SigningKeyID string `json:"signing_key_id"`
	PublicKey    string `json:"public_key"`
	Body         string `json:"body"`
	Signature    string `json:"signature"`
}

// IPSSigningKeyID derives the edge trust-store key id from an Ed25519
// public key: the lowercase-hex of its first 8 bytes (16 hex chars),
// matching sng_ips::rules::IpsSigningKeyId.
func IPSSigningKeyID(pub ed25519.PublicKey) string {
	if len(pub) < 8 {
		return ""
	}
	return hex.EncodeToString(pub[:8])
}

// SignIPSRuleBundle encodes the claims to MessagePack, signs the body
// with the signer's Ed25519 key, and returns the wire envelope. The
// signing_key_id is derived from the public key so the edge can pin
// the matching verifying key.
func (s *Signer) SignIPSRuleBundle(claims IPSRuleBundleClaims) (SignedIPSRuleBundle, error) {
	if s == nil {
		return SignedIPSRuleBundle{}, errors.New("threatintel: nil signer")
	}
	body, err := claims.EncodeBody()
	if err != nil {
		return SignedIPSRuleBundle{}, err
	}
	sig := ed25519.Sign(s.priv, body)
	return SignedIPSRuleBundle{
		Algorithm:    Algorithm,
		SigningKeyID: IPSSigningKeyID(s.Public()),
		PublicKey:    base64.StdEncoding.EncodeToString(s.Public()),
		Body:         base64.StdEncoding.EncodeToString(body),
		Signature:    base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Marshal serializes the envelope to JSON for publication.
func (e SignedIPSRuleBundle) Marshal() ([]byte, error) {
	out, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("threatintel: marshal signed ips rule bundle: %w", err)
	}
	return out, nil
}

// DecodedBody returns the raw MessagePack body bytes and the decoded
// signature, used by tests and any in-process verifier. The edge does
// the authoritative verify+decode in Rust.
func (e SignedIPSRuleBundle) DecodedBody() (body, signature []byte, err error) {
	body, err = base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("threatintel: decode ips bundle body: %w", err)
	}
	signature, err = base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("threatintel: decode ips bundle signature: %w", err)
	}
	return body, signature, nil
}

// VerifyWith checks the envelope's signature against the supplied
// pinned public key and, on success, decodes the claims. Mirrors the
// edge's verify-before-decode posture so a tampered or untrusted body
// is never parsed into the data model.
func (e SignedIPSRuleBundle) VerifyWith(pub ed25519.PublicKey) (IPSRuleBundleClaims, error) {
	if e.Algorithm != Algorithm {
		return IPSRuleBundleClaims{}, fmt.Errorf("%w: unexpected algorithm %q", ErrSignatureMismatch, e.Algorithm)
	}
	if len(pub) != ed25519.PublicKeySize {
		return IPSRuleBundleClaims{}, fmt.Errorf("%w: invalid public key length %d", ErrSignatureMismatch, len(pub))
	}
	body, sig, err := e.DecodedBody()
	if err != nil {
		return IPSRuleBundleClaims{}, err
	}
	if !ed25519.Verify(pub, body, sig) {
		return IPSRuleBundleClaims{}, ErrSignatureMismatch
	}
	var claims IPSRuleBundleClaims
	if err := msgpack.Unmarshal(body, &claims); err != nil {
		return IPSRuleBundleClaims{}, fmt.Errorf("threatintel: decode ips rule claims: %w", err)
	}
	return claims, nil
}
