package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func newTestCA(t *testing.T, store CertAuthorityStore, sealer CredentialSealer) *CertAuthority {
	t.Helper()
	ca, err := NewCertAuthority(store, sealer, nil)
	if err != nil {
		t.Fatalf("NewCertAuthority: %v", err)
	}
	return ca
}

// verifyDeviceChain asserts that the leaf certificate in chainPEM
// (device cert first, CA cert second) verifies against anchorPEM as the
// sole trust root for client authentication at time at.
func verifyDeviceChain(t *testing.T, chainPEM, anchorPEM string, at time.Time) {
	t.Helper()
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("chain has no leaf certificate: %q", chainPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(anchorPEM)) {
		t.Fatalf("anchor not added to pool")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("device cert does not verify against tenant CA: %v", err)
	}
}

func mustEd25519Pub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return pub
}

func TestNewCertAuthorityRejectsNilDeps(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	if _, err := NewCertAuthority(nil, policy.PassthroughWrapper{}, nil); err == nil {
		t.Fatal("expected error for nil store")
	}
	if _, err := NewCertAuthority(memory.NewDeviceCARepository(s), nil, nil); err == nil {
		t.Fatal("expected error for nil sealer")
	}
}

// TestCertAuthorityStableTrustAnchor is the core regression guard against
// the ephemeral-CA stub: the anchor must not change between calls, and
// every device certificate must chain to that one anchor.
func TestCertAuthorityStableTrustAnchor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.NewStore()
	ca := newTestCA(t, memory.NewDeviceCARepository(s), policy.PassthroughWrapper{})
	tenant := uuid.New()

	anchor1, err := ca.AnchorPEM(ctx, tenant)
	if err != nil {
		t.Fatalf("AnchorPEM #1: %v", err)
	}
	anchor2, err := ca.AnchorPEM(ctx, tenant)
	if err != nil {
		t.Fatalf("AnchorPEM #2: %v", err)
	}
	if anchor1 != anchor2 {
		t.Fatal("CA anchor changed between calls; it must be stable")
	}

	now := time.Now().UTC()
	c1, err := ca.Issue(ctx, tenant, uuid.New(), mustEd25519Pub(t), now, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue #1: %v", err)
	}
	c2, err := ca.Issue(ctx, tenant, uuid.New(), mustEd25519Pub(t), now, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue #2: %v", err)
	}
	if c1.Serial == c2.Serial {
		t.Fatal("two issued certs must have distinct serials")
	}
	verifyDeviceChain(t, c1.ChainPEM, anchor1, now.Add(time.Hour))
	verifyDeviceChain(t, c2.ChainPEM, anchor1, now.Add(time.Hour))
}

// TestCertAuthorityPersistsAcrossInstances proves the CA is durable: a
// second CertAuthority over the same store (empty in-process cache) loads
// the persisted CA rather than minting a new one.
func TestCertAuthorityPersistsAcrossInstances(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.NewStore()
	tenant := uuid.New()

	ca1 := newTestCA(t, memory.NewDeviceCARepository(s), policy.PassthroughWrapper{})
	anchor1, err := ca1.AnchorPEM(ctx, tenant)
	if err != nil {
		t.Fatalf("ca1 AnchorPEM: %v", err)
	}

	ca2 := newTestCA(t, memory.NewDeviceCARepository(s), policy.PassthroughWrapper{})
	anchor2, err := ca2.AnchorPEM(ctx, tenant)
	if err != nil {
		t.Fatalf("ca2 AnchorPEM: %v", err)
	}
	if anchor1 != anchor2 {
		t.Fatal("CA anchor is not stable across CertAuthority instances backed by the same store")
	}

	now := time.Now().UTC()
	c, err := ca2.Issue(ctx, tenant, uuid.New(), mustEd25519Pub(t), now, 24*time.Hour)
	if err != nil {
		t.Fatalf("ca2 Issue: %v", err)
	}
	verifyDeviceChain(t, c.ChainPEM, anchor1, now.Add(time.Hour))
}

// TestCertAuthorityIsolatesTenants confirms each tenant gets its own CA
// and a device cert from one tenant does not verify under another's.
func TestCertAuthorityIsolatesTenants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.NewStore()
	ca := newTestCA(t, memory.NewDeviceCARepository(s), policy.PassthroughWrapper{})
	tenantA := uuid.New()
	tenantB := uuid.New()

	anchorA, err := ca.AnchorPEM(ctx, tenantA)
	if err != nil {
		t.Fatalf("AnchorPEM A: %v", err)
	}
	anchorB, err := ca.AnchorPEM(ctx, tenantB)
	if err != nil {
		t.Fatalf("AnchorPEM B: %v", err)
	}
	if anchorA == anchorB {
		t.Fatal("two tenants must not share a CA")
	}

	now := time.Now().UTC()
	c, err := ca.Issue(ctx, tenantA, uuid.New(), mustEd25519Pub(t), now, 24*time.Hour)
	if err != nil {
		t.Fatalf("Issue A: %v", err)
	}
	verifyDeviceChain(t, c.ChainPEM, anchorA, now.Add(time.Hour))

	block, _ := pem.Decode([]byte(c.ChainPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(anchorB)) {
		t.Fatal("anchor B not added to pool")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now.Add(time.Hour),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("tenant A device cert must NOT verify under tenant B's CA")
	}
}

// TestCertAuthoritySealsPrivateKeyAtRest verifies the CA private key is
// sealed before persistence: under AES-GCM the stored bytes are not a
// parseable plaintext key, unseal recovers a usable key, and the seal is
// bound to the owning tenant via AAD.
func TestCertAuthoritySealsPrivateKeyAtRest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := memory.NewStore()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("master key: %v", err)
	}
	wrapper, err := policy.NewAESGCMWrapper(master)
	if err != nil {
		t.Fatalf("NewAESGCMWrapper: %v", err)
	}
	repo := memory.NewDeviceCARepository(s)
	ca := newTestCA(t, repo, wrapper)
	tenant := uuid.New()
	if _, err := ca.AnchorPEM(ctx, tenant); err != nil {
		t.Fatalf("AnchorPEM: %v", err)
	}

	stored, err := repo.GetCA(ctx, tenant)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if len(stored.PrivateKeySealed) == 0 {
		t.Fatal("stored CA private key is empty")
	}
	if _, err := x509.ParsePKCS8PrivateKey(stored.PrivateKeySealed); err == nil {
		t.Fatal("stored CA private key parses as plaintext PKCS#8; it was not sealed")
	}

	plain, err := wrapper.Unwrap(ctx, tenant, stored.PrivateKeySealed)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(plain); err != nil {
		t.Fatalf("unsealed key is not valid PKCS#8: %v", err)
	}
	if _, err := wrapper.Unwrap(ctx, uuid.New(), stored.PrivateKeySealed); err == nil {
		t.Fatal("sealed CA key unsealed under the wrong tenant AAD; tenant isolation broken")
	}
}

// raceCAStore forces the bootstrap conflict path: the first GetCA misses
// (so the authority bootstraps), CreateCA always loses the insert
// (ErrConflict), and the recovery GetCA returns the winning CA.
type raceCAStore struct {
	winner repository.DeviceCA
	gets   int
}

func (r *raceCAStore) GetCA(_ context.Context, _ uuid.UUID) (repository.DeviceCA, error) {
	r.gets++
	if r.gets == 1 {
		return repository.DeviceCA{}, repository.ErrNotFound
	}
	return r.winner, nil
}

func (r *raceCAStore) CreateCA(_ context.Context, _ uuid.UUID, _ repository.DeviceCA) (repository.DeviceCA, error) {
	return repository.DeviceCA{}, repository.ErrConflict
}

// TestCertAuthorityRecoversFromBootstrapRace exercises the ErrConflict
// branch: a CertAuthority that loses the persist race must adopt the
// winning CA and issue certs that verify against it.
func TestCertAuthorityRecoversFromBootstrapRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tenant := uuid.New()

	// Produce a real winning CA via a memory-backed authority.
	ws := memory.NewStore()
	wrepo := memory.NewDeviceCARepository(ws)
	winnerCA := newTestCA(t, wrepo, policy.PassthroughWrapper{})
	winnerAnchor, err := winnerCA.AnchorPEM(ctx, tenant)
	if err != nil {
		t.Fatalf("winner AnchorPEM: %v", err)
	}
	winnerRow, err := wrepo.GetCA(ctx, tenant)
	if err != nil {
		t.Fatalf("winner GetCA: %v", err)
	}

	loser := newTestCA(t, &raceCAStore{winner: winnerRow}, policy.PassthroughWrapper{})
	anchor, err := loser.AnchorPEM(ctx, tenant)
	if err != nil {
		t.Fatalf("loser AnchorPEM: %v", err)
	}
	if anchor != winnerAnchor {
		t.Fatal("bootstrap-race loser did not adopt the winning CA")
	}

	now := time.Now().UTC()
	c, err := loser.Issue(ctx, tenant, uuid.New(), mustEd25519Pub(t), now, 24*time.Hour)
	if err != nil {
		t.Fatalf("loser Issue: %v", err)
	}
	verifyDeviceChain(t, c.ChainPEM, winnerAnchor, now.Add(time.Hour))
}

// TestEnrollmentServiceUsesPersistentCA exercises the full enrollment
// path: an enrolled device's certificate verifies against the tenant CA
// reported by GetTenantCA, and a refresh issues a new cert under the same
// anchor.
func TestEnrollmentServiceUsesPersistentCA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, tenantID, tokens := newEnrollmentService(t)
	plaintext := seedClaimToken(t, tokens, tenantID)
	deviceID := uuid.New()

	res, err := svc.RedeemClaimToken(ctx, tenantID, deviceID, plaintext, generateEd25519PublicKey(t))
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}

	anchor, err := svc.GetTenantCA(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantCA: %v", err)
	}
	now := time.Now().UTC()
	verifyDeviceChain(t, res.Certificate.CertPEM, anchor, now)

	refreshed, err := svc.RefreshCertificate(ctx, tenantID, deviceID)
	if err != nil {
		t.Fatalf("RefreshCertificate: %v", err)
	}
	if refreshed.Serial == res.Certificate.Serial {
		t.Fatal("refresh must mint a new certificate serial")
	}
	anchorAfter, err := svc.GetTenantCA(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetTenantCA after refresh: %v", err)
	}
	if anchor != anchorAfter {
		t.Fatal("CA anchor changed after certificate refresh")
	}
	verifyDeviceChain(t, refreshed.CertPEM, anchor, now)
}
