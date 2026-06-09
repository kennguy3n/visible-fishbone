// keyprovider.go defines the customer-managed-key (CMK) abstraction
// for the ShieldNet Gateway control plane (WS9 — Security &
// Compliance).
//
// Historically only the Data Guard tier carried CMK, and the at-rest
// crypto seam was the policy.PrivateKeyWrapper (Wrap/Unwrap of an
// Ed25519 seed). WS9 generalises that into a tier-independent envelope
// scheme: every plane that persists regulated tenant data —
// telemetry, policy bundles, cold-storage archives, RBI artifacts —
// encrypts it with a per-object data-encryption key (DEK) that is
// itself wrapped under the tenant's key-encryption key (KEK). The KEK
// is either the platform's own key (the default, "no-CMK" tier) or a
// customer-managed key held in the tenant's cloud KMS (AWS KMS, Azure
// Key Vault, GCP KMS). The platform never holds CMK material; it only
// asks the KMS to wrap/unwrap DEKs.
//
// This file is the SDK-free core: the TenantKeyProvider interface, the
// value types that cross it, reference validation, and the provider
// registry. It deliberately imports no cloud SDK — the concrete AWS /
// Azure / GCP adapters are wired in cmd/sng-control, exactly as the
// compliance.ObjectStore (S3) and policy KMS wrappers are. That keeps
// the residency package, and its tests, free of the cloud SDKs and
// lets the envelope logic be exhaustively unit-tested against the
// in-process LocalKeyProvider.
package residency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
)

// PlaneKeyManagement is the residency plane for KEK/DEK operations.
// Unlike the data planes it is never written to the residency_audit
// table (migration 046's CHECK constraint covers only the data
// planes); a CMK region-binding rejection is surfaced as a Violation
// and audited through the platform audit log by the CMKService. It
// exists so a fail-closed key-management rejection carries the same
// structured plane context as a data-plane rejection.
const PlaneKeyManagement Plane = "key_management"

// KeyProviderKind identifies the external KMS backing a tenant's
// key-encryption key. The string values are stable: they are
// persisted on the tenant record and used as the registry dispatch
// key, so they must not change without a migration.
type KeyProviderKind string

const (
	// ProviderPlatform is the default platform-managed KEK. There is
	// no customer-managed key; the platform's own master key (held in
	// the deployment's KMS / sealed secret) wraps tenant DEKs. This is
	// the "no-CMK" tier and the fallback when a tenant has not opted
	// into CMK.
	ProviderPlatform KeyProviderKind = "platform"
	// ProviderAWSKMS is an AWS KMS customer master key (symmetric,
	// ENCRYPT_DECRYPT key usage).
	ProviderAWSKMS KeyProviderKind = "aws_kms"
	// ProviderAzureKV is an Azure Key Vault / Managed HSM key.
	ProviderAzureKV KeyProviderKind = "azure_kv"
	// ProviderGCPKMS is a Google Cloud KMS crypto key.
	ProviderGCPKMS KeyProviderKind = "gcp_kms"
)

// dekSize is the byte length of a data-encryption key. 32 bytes binds
// the DEK to AES-256, matching the AES-256-GCM sealing used by the
// telemetry cold-archive and the policy key wrapper.
const dekSize = 32

var (
	// ErrUnknownProvider is returned when a TenantKeyRef names a
	// provider kind that has no registered implementation. It is
	// fail-closed: a key operation against an unwired provider is
	// rejected, never silently downgraded to plaintext.
	ErrUnknownProvider = errors.New("residency: unknown key provider")
	// ErrInvalidKeyRef is returned when a TenantKeyRef is malformed —
	// an unknown kind, an empty/oversized KeyURI, or a KeyURI that does
	// not match the provider's required shape.
	ErrInvalidKeyRef = errors.New("residency: invalid tenant key reference")
	// ErrProviderKindMismatch is returned when a wrapped DEK is handed
	// to a provider of a different kind than the one that produced it.
	ErrProviderKindMismatch = errors.New("residency: wrapped key provider kind mismatch")
	// ErrWrapFailed wraps any KMS-side failure to wrap a DEK.
	ErrWrapFailed = errors.New("residency: data-key wrap failed")
	// ErrUnwrapFailed wraps any KMS-side failure to unwrap a DEK
	// (wrong key, wrong encryption context, tampered ciphertext). It
	// is deliberately coarse so a caller cannot distinguish the cause
	// by error inspection.
	ErrUnwrapFailed = errors.New("residency: data-key unwrap failed")
)

// maxKeyURILen bounds a KeyURI so a malformed/hostile value cannot be
// persisted or logged unboundedly. Real ARNs, Key Vault URLs and GCP
// resource names are comfortably under this.
const maxKeyURILen = 512

// TenantKeyRef is a validated reference to the key-encryption key used
// for a tenant. It is the residency-aware handle the CMKService and
// every TenantKeyProvider operate on.
//
// Region is the region the KEK lives in. For a CMK it MUST equal the
// tenant's designated data-residency region (the CMKService enforces
// this fail-closed) so key material never leaves the jurisdiction the
// data is pinned to. For ProviderPlatform the region is the control
// plane's own region.
type TenantKeyRef struct {
	// TenantID is the tenant the key belongs to. It is bound into the
	// encryption context of every operation so a DEK wrapped for one
	// tenant can never be unwrapped under another, even on the same
	// KEK.
	TenantID uuid.UUID
	// Kind selects the provider implementation.
	Kind KeyProviderKind
	// Region is the KMS region/location the KEK resides in.
	Region Region
	// KeyURI is the provider-native key identifier:
	//   - aws_kms : key ARN (arn:aws:kms:<region>:<acct>:key/<id>) or
	//               alias ARN.
	//   - azure_kv: versioned key URL
	//               (https://<vault>.vault.azure.net/keys/<name>/<ver>).
	//   - gcp_kms : crypto-key resource name
	//               (projects/.../locations/<loc>/keyRings/.../cryptoKeys/...).
	//   - platform: empty (the provider's default key) or an opaque
	//               key id for key rotation across platform masters.
	KeyURI string
}

// IsCMK reports whether the ref designates a customer-managed key (as
// opposed to the platform-managed default). CMK is opt-in: a zero-kind
// or platform-kind ref is platform-managed.
func (r TenantKeyRef) IsCMK() bool {
	return r.Kind != "" && r.Kind != ProviderPlatform
}

// keyURIPattern bounds each provider's KeyURI to its real shape so a
// misconfiguration (e.g. an AWS ARN pasted into an Azure tenant
// record) fails loudly at validation time rather than at the first
// production unwrap.
var keyURIPattern = map[KeyProviderKind]*regexp.Regexp{
	ProviderAWSKMS: regexp.MustCompile(
		`^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)/[A-Za-z0-9/_-]+$`),
	ProviderAzureKV: regexp.MustCompile(
		// Vault/HSM name: 3-24 chars, alphanumeric start and end, hyphens
		// only in the interior — matching Azure's own naming rule so an
		// obviously malformed name (leading/trailing hyphen) is rejected
		// here rather than at the first production call.
		`^https://[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.(vault\.azure\.net|managedhsm\.azure\.net)/keys/[A-Za-z0-9-]+(/[0-9a-f]{32})?$`),
	ProviderGCPKMS: regexp.MustCompile(
		`^projects/[a-z0-9-]+/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+(/cryptoKeyVersions/\d+)?$`),
}

// Validate checks the ref is structurally usable: a recognised kind, a
// non-empty tenant, a well-formed region, and a KeyURI matching the
// provider's shape. It does NOT contact any KMS and does NOT enforce
// the region-residency binding — that is the CMKService's job, because
// it needs the tenant's designated region to compare against.
func (r TenantKeyRef) Validate() error {
	if r.TenantID == uuid.Nil {
		return fmt.Errorf("%w: empty tenant id", ErrInvalidKeyRef)
	}
	switch r.Kind {
	case ProviderPlatform:
		// Platform KeyURI is optional (empty = default master); if
		// present it is an opaque id, only length-bounded.
		if len(r.KeyURI) > maxKeyURILen {
			return fmt.Errorf("%w: platform key id too long", ErrInvalidKeyRef)
		}
		return nil
	case ProviderAWSKMS, ProviderAzureKV, ProviderGCPKMS:
		if err := ValidateRegion(r.Region); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKeyRef, err)
		}
		if r.KeyURI == "" || len(r.KeyURI) > maxKeyURILen {
			return fmt.Errorf("%w: %s KeyURI must be 1..%d chars", ErrInvalidKeyRef, r.Kind, maxKeyURILen)
		}
		if pat := keyURIPattern[r.Kind]; pat != nil && !pat.MatchString(r.KeyURI) {
			return fmt.Errorf("%w: %s KeyURI %q does not match the expected shape", ErrInvalidKeyRef, r.Kind, r.KeyURI)
		}
		return nil
	default:
		return fmt.Errorf("%w: kind %q", ErrInvalidKeyRef, r.Kind)
	}
}

// WrappedDataKey is a provider-opaque envelope around a DEK: the
// ciphertext the KMS returned plus the metadata needed to unwrap it
// later. It is what callers persist alongside the data the DEK
// encrypted (e.g. in an object header or a DB column).
type WrappedDataKey struct {
	// Kind and KeyURI identify the KEK that wrapped the DEK so a later
	// unwrap routes to the same provider/key even after the tenant
	// rotates to a different KEK.
	Kind   KeyProviderKind `json:"kind"`
	KeyURI string          `json:"key_uri"`
	// Ciphertext is the KMS-wrapped DEK. Its internal structure is the
	// provider's concern (for AWS KMS it is the CiphertextBlob; for the
	// LocalKeyProvider it is nonce||ciphertext||tag).
	Ciphertext []byte `json:"ciphertext"`
	// KeyVersion records the KEK version at wrap time, when the
	// provider exposes one (GCP cryptoKeyVersion, Azure key version,
	// AWS key rotation has no caller-visible version so it is empty).
	// It is advisory metadata for rotation auditing, not used in the
	// unwrap path.
	KeyVersion string `json:"key_version,omitempty"`
}

// DataKey is the result of GenerateDataKey: a freshly minted DEK in
// both plaintext (to encrypt data with, then zeroize) and wrapped (to
// persist) form.
type DataKey struct {
	// Plaintext is the raw 32-byte DEK. The caller MUST Zeroize it as
	// soon as the data is encrypted; it must never be persisted or
	// logged.
	Plaintext []byte
	// Wrapped is the CMK/KEK-wrapped DEK, safe to persist.
	Wrapped WrappedDataKey
}

// Zeroize wipes the plaintext DEK. Safe to call on a zero DataKey.
func (d *DataKey) Zeroize() {
	Zeroize(d.Plaintext)
}

// Zeroize overwrites b with zeros. It is a best-effort defence to
// shorten the window a DEK sits in process memory; Go may still have
// copied the slice (escape analysis, GC), so it is not a guarantee,
// only a reduction of exposure consistent with the rest of the
// codebase's handling of seeds.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncryptionContext is additional authenticated data bound into every
// wrap/unwrap. It is cryptographically enforced: a DEK wrapped with a
// given context can only be unwrapped by supplying the identical
// context (AWS KMS encryption context, GCP additionalAuthenticatedData,
// and the LocalKeyProvider's GCM AAD all enforce this). The CMKService
// always binds the tenant id; callers may add a plane or object scope.
//
// It is a small string map; order does not matter because Canonical
// sorts keys.
type EncryptionContext map[string]string

// Canonical returns a deterministic byte encoding of the context for
// use as AAD. encoding/json marshals map[string]string with sorted
// keys, so the encoding is stable across processes and independent of
// insertion order — the property AAD comparison requires.
func (ec EncryptionContext) Canonical() []byte {
	if len(ec) == 0 {
		return []byte("{}")
	}
	out, _ := json.Marshal(map[string]string(ec))
	return out
}

// clone returns a copy so the caller's map cannot be mutated by the
// service after it injects the tenant binding.
func (ec EncryptionContext) clone() EncryptionContext {
	out := make(EncryptionContext, len(ec)+1)
	for k, v := range ec {
		out[k] = v
	}
	return out
}

// ContextTenantID is the reserved encryption-context key the CMKService
// binds the tenant UUID under. Callers must not set it themselves; a
// conflicting value is rejected fail-closed.
const ContextTenantID = "tenant_id"

// TenantKeyProvider performs envelope encryption under a tenant's KEK.
// Implementations wrap a single KMS family (AWS KMS, Azure Key Vault,
// GCP KMS) or the platform's own master key. They are stateless and
// safe for concurrent use.
//
// The provider never sees plane/data — only DEK material — and never
// holds the KEK: GenerateDataKey and UnwrapDataKey are remote calls to
// the KMS (or, for LocalKeyProvider, in-process AEAD). Callers reach
// providers through the CMKService, which adds tenant resolution and
// the residency region-binding check; providers are not meant to be
// called directly from data planes.
type TenantKeyProvider interface {
	// Kind reports which KMS family this provider serves. It must
	// equal the Kind of every ref/wrapped key it is asked to handle.
	Kind() KeyProviderKind
	// GenerateDataKey asks the KEK named by ref to mint a new DEK,
	// returning it in plaintext and wrapped form, with ec bound as
	// additional authenticated data. Implementations must fail closed:
	// any KMS error returns a non-nil error and a zero DataKey, never
	// a usable plaintext with an unverified wrap.
	GenerateDataKey(ctx context.Context, ref TenantKeyRef, ec EncryptionContext) (DataKey, error)
	// UnwrapDataKey decrypts wrapped under the KEK named by ref, with
	// ec bound as additional authenticated data. ec must be identical
	// to the context used at wrap time or the unwrap fails.
	UnwrapDataKey(ctx context.Context, ref TenantKeyRef, wrapped WrappedDataKey, ec EncryptionContext) ([]byte, error)
}

// KeyProviderRegistry maps a KeyProviderKind to its implementation. It
// is built once at wiring time (cmd/sng-control registers the cloud
// adapters; tests register a LocalKeyProvider) and is read-only
// thereafter, so it needs no locking.
type KeyProviderRegistry struct {
	providers map[KeyProviderKind]TenantKeyProvider
}

// NewKeyProviderRegistry builds a registry from the given providers.
// It returns an error if two providers report the same Kind or a
// provider reports an empty Kind, so a misconfiguration is caught at
// startup rather than at the first key operation.
func NewKeyProviderRegistry(providers ...TenantKeyProvider) (*KeyProviderRegistry, error) {
	m := make(map[KeyProviderKind]TenantKeyProvider, len(providers))
	for _, p := range providers {
		if p == nil {
			return nil, errors.New("residency: nil key provider")
		}
		k := p.Kind()
		if k == "" {
			return nil, errors.New("residency: key provider reports empty kind")
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("residency: duplicate key provider for kind %q", k)
		}
		m[k] = p
	}
	return &KeyProviderRegistry{providers: m}, nil
}

// For returns the provider for kind, or ErrUnknownProvider when none
// is registered (fail-closed).
func (r *KeyProviderRegistry) For(kind KeyProviderKind) (TenantKeyProvider, error) {
	if p, ok := r.providers[kind]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, kind)
}

// Kinds returns the registered provider kinds (unordered). Used by
// readiness checks and the admin surface to report enabled CMK
// backends.
func (r *KeyProviderRegistry) Kinds() []KeyProviderKind {
	out := make([]KeyProviderKind, 0, len(r.providers))
	for k := range r.providers {
		out = append(out, k)
	}
	return out
}
