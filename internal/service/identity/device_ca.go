package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultCATTL is the validity period of a tenant's device CA. Device
// certificates are short-lived (DefaultCertTTL, 24h) and refreshed, but
// the CA that signs them is the long-lived trust anchor an mTLS verifier
// pins, so it must outlive many device-cert generations. Rotation is
// out of scope for v1 (deferred to a dedicated CA-rotation flow).
const DefaultCATTL = 10 * 365 * 24 * time.Hour

// CertAuthorityStore is the persistence seam for per-tenant device CAs.
// repository.DeviceCARepository satisfies it; the indirection keeps the
// identity layer free of a concrete repository dependency and lets tests
// substitute an in-memory store.
type CertAuthorityStore interface {
	GetCA(ctx context.Context, tenantID uuid.UUID) (repository.DeviceCA, error)
	CreateCA(ctx context.Context, tenantID uuid.UUID, ca repository.DeviceCA) (repository.DeviceCA, error)
}

// caMaterial is a tenant's unsealed, ready-to-sign CA, cached in process
// after first use so steady-state issuance does no DB round-trip or
// unseal.
type caMaterial struct {
	cert    *x509.Certificate
	certPEM string
	priv    ed25519.PrivateKey
}

// IssuedCert is a freshly signed device certificate plus the metadata
// the enrollment service needs to persist and return it.
type IssuedCert struct {
	Serial    string
	ChainPEM  string
	NotBefore time.Time
	NotAfter  time.Time
}

// CertAuthority issues device certificates from a stable, persistent
// per-tenant CA. The CA is bootstrapped lazily on first use (generate →
// seal private key at rest → persist), cached unsealed in process, and
// shared by every device certificate the tenant ever issues so a single
// trust anchor can be pinned by the data plane.
type CertAuthority struct {
	store   CertAuthorityStore
	sealer  CredentialSealer
	logger  *slog.Logger
	caTTL   time.Duration
	nowFunc func() time.Time

	mu    sync.RWMutex
	cache map[uuid.UUID]*caMaterial
}

// NewCertAuthority constructs a CertAuthority. The sealer wraps the CA
// private key at rest; pass policy.PassthroughWrapper for dev / TDE
// deployments or policy.AESGCMWrapper when a key-wrap master is set.
func NewCertAuthority(store CertAuthorityStore, sealer CredentialSealer, logger *slog.Logger) (*CertAuthority, error) {
	if store == nil {
		return nil, errors.New("identity: device CA store is required")
	}
	if sealer == nil {
		return nil, errors.New("identity: device CA sealer is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &CertAuthority{
		store:   store,
		sealer:  sealer,
		logger:  logger,
		caTTL:   DefaultCATTL,
		nowFunc: func() time.Time { return time.Now().UTC() },
		cache:   make(map[uuid.UUID]*caMaterial),
	}, nil
}

// AnchorPEM returns the tenant's CA certificate in PEM form — the trust
// anchor an mTLS verifier pins to validate device certificates. The CA
// is bootstrapped on demand if the tenant has none yet.
func (a *CertAuthority) AnchorPEM(ctx context.Context, tenantID uuid.UUID) (string, error) {
	m, err := a.caFor(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return m.certPEM, nil
}

// Issue signs a device certificate binding devicePub for ttl, chaining
// it to the tenant's persistent CA. The returned ChainPEM is the device
// certificate followed by the CA certificate.
func (a *CertAuthority) Issue(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
	devicePub ed25519.PublicKey,
	now time.Time,
	ttl time.Duration,
) (IssuedCert, error) {
	if len(devicePub) != ed25519.PublicKeySize {
		return IssuedCert{}, fmt.Errorf("device public key must be %d bytes (Ed25519): %w", ed25519.PublicKeySize, repository.ErrInvalidArgument)
	}
	m, err := a.caFor(ctx, tenantID)
	if err != nil {
		return IssuedCert{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return IssuedCert{}, fmt.Errorf("generate device serial: %w", err)
	}
	notAfter := now.Add(ttl)
	deviceTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   deviceID.String(),
			Organization: []string{tenantID.String()},
		},
		NotBefore:   now,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	deviceCertDER, err := x509.CreateCertificate(rand.Reader, deviceTemplate, m.cert, devicePub, m.priv)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("create device certificate: %w", err)
	}

	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: deviceCertDER})
	chain = append(chain, []byte(m.certPEM)...)

	return IssuedCert{
		Serial:    serial.Text(16),
		ChainPEM:  string(chain),
		NotBefore: now,
		NotAfter:  notAfter,
	}, nil
}

// caFor returns the tenant's CA material, bootstrapping it on first use.
// Safe for concurrent use; a lost bootstrap race re-reads the winner so
// every caller converges on the one persisted trust anchor.
func (a *CertAuthority) caFor(ctx context.Context, tenantID uuid.UUID) (*caMaterial, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("tenant id is required: %w", repository.ErrInvalidArgument)
	}

	a.mu.RLock()
	m, ok := a.cache[tenantID]
	a.mu.RUnlock()
	if ok {
		return m, nil
	}

	stored, err := a.store.GetCA(ctx, tenantID)
	if err == nil {
		return a.materializeAndCache(ctx, tenantID, stored)
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("load device CA: %w", err)
	}

	return a.bootstrap(ctx, tenantID)
}

// bootstrap generates a fresh CA for the tenant, seals its private key,
// and persists it. If a concurrent caller wins the insert (ErrConflict),
// it re-reads and adopts the winning CA instead of overwriting it.
func (a *CertAuthority) bootstrap(ctx context.Context, tenantID uuid.UUID) (*caMaterial, error) {
	now := a.nowFunc()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SNG Device CA - " + tenantID.String(),
			Organization: []string{tenantID.String()},
		},
		NotBefore:             now,
		NotAfter:              now.Add(a.caTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, caPub, caPriv)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	pkcs8, err := x509.MarshalPKCS8PrivateKey(caPriv)
	if err != nil {
		return nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	sealed, err := a.sealer.Wrap(ctx, tenantID, pkcs8)
	if err != nil {
		return nil, fmt.Errorf("seal CA private key: %w", err)
	}

	_, err = a.store.CreateCA(ctx, tenantID, repository.DeviceCA{
		TenantID:         tenantID,
		CertPEM:          certPEM,
		PrivateKeySealed: sealed,
		CreatedAt:        now,
	})
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			// Another node bootstrapped first; adopt the winner.
			stored, getErr := a.store.GetCA(ctx, tenantID)
			if getErr != nil {
				return nil, fmt.Errorf("reload device CA after bootstrap race: %w", getErr)
			}
			return a.materializeAndCache(ctx, tenantID, stored)
		}
		return nil, fmt.Errorf("persist device CA: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	a.logger.Info("device enrollment: bootstrapped persistent tenant CA",
		slog.String("tenantID", tenantID.String()),
		slog.Time("notAfter", template.NotAfter))
	return a.store2cache(tenantID, &caMaterial{cert: cert, certPEM: certPEM, priv: caPriv}), nil
}

// materializeAndCache unseals and parses a stored CA into ready-to-sign
// material and caches it. The caller's context is forwarded to the unseal so a
// network-backed sealer (e.g. a KMS) honours request deadlines, cancellation,
// and tracing rather than running detached.
func (a *CertAuthority) materializeAndCache(ctx context.Context, tenantID uuid.UUID, stored repository.DeviceCA) (*caMaterial, error) {
	block, _ := pem.Decode([]byte(stored.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("device CA for tenant %s has malformed certificate PEM", tenantID)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse stored CA certificate: %w", err)
	}
	pkcs8, err := a.sealer.Unwrap(ctx, tenantID, stored.PrivateKeySealed)
	if err != nil {
		return nil, fmt.Errorf("unseal CA private key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("parse CA private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("device CA private key for tenant %s is not Ed25519", tenantID)
	}
	return a.store2cache(tenantID, &caMaterial{cert: cert, certPEM: stored.CertPEM, priv: priv}), nil
}

// store2cache caches material under a write lock, returning whichever
// material wins if a concurrent caller cached first (so all callers
// share one instance of the tenant's trust anchor).
func (a *CertAuthority) store2cache(tenantID uuid.UUID, m *caMaterial) *caMaterial {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.cache[tenantID]; ok {
		return existing
	}
	a.cache[tenantID] = m
	return m
}
