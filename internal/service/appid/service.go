// Package appid is the control-plane service for the fleet-wide
// Application-ID signature catalog. It owns the operator-managed,
// versioned catalog: each published version is recorded in Postgres
// and distributed to tenants as an Ed25519-signed bundle, mirroring
// how the platform already ships threat-intel and policy bundles.
//
// The catalog is centrally managed and identical for every tenant
// (no per-tenant configuration — a no-ops requirement for the 5,000
// SME tenants the platform serves). Tenants PULL the current signed
// bundle through the tenant-scoped read API and verify it against a
// pinned key before use; an optional push publisher fans new versions
// out over the message bus when one is wired.
package appid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// seedJSON is the embedded seed catalog. It is kept byte-identical to
// the Rust crate's canonical crates/sng-appid/data/catalog.json (an
// invariant test guards the two copies) so the control plane and the
// data plane ship the same signatures. Go's embed cannot reference a
// path outside its package directory, which is why this is a checked-in
// copy rather than a symlink.
//
//go:embed catalog_seed.json
var seedJSON []byte

// DefaultSubject is the message-bus subject new signed bundles are
// published to when a push publisher is configured.
const DefaultSubject = "sng.appid.catalog.bundle"

// BundlePublisher fans a freshly published signed bundle out to edges
// over the message bus. It is optional: when nil, the service is
// pull-only (edges fetch the current bundle via the read API).
type BundlePublisher interface {
	PublishBundle(ctx context.Context, subject string, data []byte) error
}

// seedCatalog is the on-disk schema of catalog_seed.json — the same
// shape as the Rust crate's catalog.json (schema_version + apps).
type seedCatalog struct {
	SchemaVersion int         `json:"schema_version"`
	Apps          []BundleApp `json:"apps"`
}

// Service publishes and serves versioned, signed catalog bundles.
type Service struct {
	repo      repository.AppIDCatalogRepository
	signer    *Signer
	keyID     string
	publisher BundlePublisher
	subject   string
	logger    *slog.Logger
	now       func() time.Time

	// seedApps is the validated embedded catalog, parsed once at
	// construction and used to seed an empty store.
	seedApps []BundleApp
}

// Option configures a Service.
type Option func(*Service)

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithKeyID labels published bundles with a signing-key identifier so
// consumers can select the matching pinned verifying key.
func WithKeyID(id string) Option { return func(s *Service) { s.keyID = id } }

// WithSubject overrides the publish subject.
func WithSubject(subject string) Option {
	return func(s *Service) {
		if subject != "" {
			s.subject = subject
		}
	}
}

// WithPublisher attaches an optional push publisher.
func WithPublisher(p BundlePublisher) Option { return func(s *Service) { s.publisher = p } }

// withClock overrides the clock (tests only).
func withClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New constructs the service. repo and signer are required; a nil
// signer is rejected because an unsigned catalog must never be
// distributed. The embedded seed is parsed and validated up front so a
// malformed seed fails fast at boot rather than at first publish.
func New(repo repository.AppIDCatalogRepository, signer *Signer, opts ...Option) (*Service, error) {
	if repo == nil {
		return nil, errors.New("appid: nil repository")
	}
	if signer == nil {
		return nil, errors.New("appid: nil signer")
	}
	apps, err := parseSeed(seedJSON)
	if err != nil {
		return nil, fmt.Errorf("appid: load seed catalog: %w", err)
	}
	s := &Service{
		repo:     repo,
		signer:   signer,
		subject:  DefaultSubject,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      time.Now,
		seedApps: apps,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// SeedCount reports the number of apps in the embedded seed catalog.
func (s *Service) SeedCount() int { return len(s.seedApps) }

// PublicKey returns the verifying key for the service's signer, so an
// in-process consumer (or test) can verify served bundles.
func (s *Service) PublicKey() ed25519.PublicKey { return s.signer.Public() }

// SeedIfEmpty publishes the embedded seed as the first catalog version
// when the store has none. It is safe to call from every replica at
// boot: the monotonic-serial constraint means only one publisher wins
// and the rest observe ErrConflict, which is treated as "already
// seeded". This is the no-ops behaviour — the fleet ships with a
// usable, signed catalog without any operator action.
func (s *Service) SeedIfEmpty(ctx context.Context) error {
	if _, err := s.repo.CurrentVersion(ctx); err == nil {
		return nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("appid: check current version: %w", err)
	}
	_, err := s.publish(ctx, s.seedApps, "initial seed")
	if errors.Is(err, repository.ErrConflict) {
		s.logger.Info("appid: catalog already seeded by another replica")
		return nil
	}
	return err
}

// Republish signs and stores the current catalog (or the embedded seed
// if nothing is published yet) as a new version with a fresh serial.
// It is the operator-triggered redistribution / key-rotation action.
func (s *Service) Republish(ctx context.Context, note string) (repository.AppIDCatalogVersion, error) {
	entries, err := s.repo.CurrentEntries(ctx)
	var apps []BundleApp
	switch {
	case errors.Is(err, repository.ErrNotFound):
		apps = s.seedApps
	case err != nil:
		return repository.AppIDCatalogVersion{}, fmt.Errorf("appid: load current entries: %w", err)
	default:
		apps = entriesToApps(entries)
	}
	return s.publish(ctx, apps, note)
}

// CurrentVersion returns the highest-serial version metadata.
func (s *Service) CurrentVersion(ctx context.Context) (repository.AppIDCatalogVersion, error) {
	return s.repo.CurrentVersion(ctx)
}

// ListVersions returns version history newest-first.
func (s *Service) ListVersions(ctx context.Context, limit int) ([]repository.AppIDCatalogVersion, error) {
	return s.repo.ListVersions(ctx, limit)
}

// CurrentBundle returns the current signed envelope together with its
// version metadata. Both are read in a single repository call so the
// envelope and the metadata (serial, app_count, checksum) always
// describe the same published version — a concurrent publish can never
// hand a tenant a payload whose checksum belongs to a different serial.
// The envelope is reconstructed from the stored raw bytes; the edge
// verifies Signature against its pinned key before use.
func (s *Service) CurrentBundle(ctx context.Context) (SignedBundle, repository.AppIDCatalogVersion, error) {
	row, ver, err := s.repo.CurrentBundleWithVersion(ctx)
	if err != nil {
		return SignedBundle{}, repository.AppIDCatalogVersion{}, err
	}
	return envelopeFromRow(row), ver, nil
}

// publish builds, signs, persists, and (optionally) pushes a new
// catalog version from apps.
func (s *Service) publish(ctx context.Context, apps []BundleApp, note string) (repository.AppIDCatalogVersion, error) {
	if len(apps) == 0 {
		return repository.AppIDCatalogVersion{}, errors.New("appid: refusing to publish an empty catalog")
	}
	serial, err := s.nextSerial(ctx)
	if err != nil {
		return repository.AppIDCatalogVersion{}, err
	}
	generatedAt := s.now().UTC()

	bundle := &CatalogBundle{
		SchemaVersion: SchemaVersion,
		Serial:        serial,
		GeneratedAt:   generatedAt,
		Apps:          cloneApps(apps),
	}
	payload, err := bundle.CanonicalBytes()
	if err != nil {
		return repository.AppIDCatalogVersion{}, err
	}
	sig := s.signer.sign(payload)
	pub := s.signer.Public()
	sum := sha256.Sum256(payload)

	version := repository.AppIDCatalogVersion{
		Serial:        serial,
		SchemaVersion: SchemaVersion,
		AppCount:      len(bundle.Apps),
		Checksum:      hex.EncodeToString(sum[:]),
		Note:          note,
		CreatedAt:     generatedAt,
	}
	row := repository.AppIDCatalogBundle{
		Serial:    serial,
		Algorithm: Algorithm,
		KeyID:     s.keyID,
		PublicKey: pub,
		Payload:   payload,
		Signature: sig,
		CreatedAt: generatedAt,
	}
	entries := appsToEntries(serial, bundle.Apps)

	if err := s.repo.PublishVersion(ctx, version, entries, row); err != nil {
		return repository.AppIDCatalogVersion{}, err
	}

	s.pushBundle(ctx, envelopeFromRow(row))
	s.logger.Info("appid: published catalog version",
		slog.Int64("serial", serial),
		slog.Int("apps", version.AppCount),
		slog.String("checksum", version.Checksum))
	return version, nil
}

// pushBundle best-effort fans the envelope out over the message bus. A
// publish failure is logged but does not fail the publish: the version
// is durably stored and edges can always pull it.
func (s *Service) pushBundle(ctx context.Context, env SignedBundle) {
	if s.publisher == nil {
		return
	}
	data, err := env.Marshal()
	if err != nil {
		s.logger.Warn("appid: marshal bundle for push failed", slog.String("error", err.Error()))
		return
	}
	if err := s.publisher.PublishBundle(ctx, s.subject, data); err != nil {
		s.logger.Warn("appid: push bundle failed", slog.String("error", err.Error()))
	}
}

// nextSerial returns a serial strictly greater than the current one,
// defaulting to producer wall-clock unix seconds so serials stay
// human-meaningful while remaining monotonic across restarts.
func (s *Service) nextSerial(ctx context.Context) (int64, error) {
	cur, err := s.repo.CurrentVersion(ctx)
	next := s.now().Unix()
	switch {
	case err == nil:
		if next <= cur.Serial {
			next = cur.Serial + 1
		}
	case errors.Is(err, repository.ErrNotFound):
		// First version — keep the wall-clock serial.
	default:
		return 0, fmt.Errorf("appid: read current serial: %w", err)
	}
	return next, nil
}

// envelopeFromRow reconstructs the base64 wire envelope from the raw
// bytes persisted in the bundle row.
func envelopeFromRow(row repository.AppIDCatalogBundle) SignedBundle {
	return SignedBundle{
		Algorithm: row.Algorithm,
		KeyID:     row.KeyID,
		PublicKey: base64.StdEncoding.EncodeToString(row.PublicKey),
		Payload:   base64.StdEncoding.EncodeToString(row.Payload),
		Signature: base64.StdEncoding.EncodeToString(row.Signature),
	}
}

// parseSeed decodes and validates the embedded seed catalog. Every app
// must declare at least one content signal (SNI, host, JA3, or byte
// prefix) — a bare port/transport entry is rejected because a port is
// only a weak modifier, never an identity. This mirrors the Rust
// crate's validation so the two copies cannot drift semantically.
func parseSeed(data []byte) ([]BundleApp, error) {
	var sc seedCatalog
	if err := json.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("parse seed json: %w", err)
	}
	if sc.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported seed schema version %d (want %d)", sc.SchemaVersion, SchemaVersion)
	}
	if len(sc.Apps) == 0 {
		return nil, errors.New("seed catalog is empty")
	}
	seen := make(map[string]struct{}, len(sc.Apps))
	for i := range sc.Apps {
		a := &sc.Apps[i]
		if a.AppID == "" || a.Category == "" {
			return nil, fmt.Errorf("seed app %d: empty app_id or category", i)
		}
		if _, dup := seen[a.AppID]; dup {
			return nil, fmt.Errorf("seed app %q: duplicate app_id", a.AppID)
		}
		seen[a.AppID] = struct{}{}
		if len(a.SNISuffixes) == 0 && len(a.HostSuffixes) == 0 && len(a.JA3) == 0 && len(a.BytePrefixes) == 0 {
			return nil, fmt.Errorf("seed app %q: no content signal (needs sni/host/ja3/byte prefix)", a.AppID)
		}
		if a.Transport == "" {
			a.Transport = "tcp"
		}
		if a.Confidence < 0 {
			a.Confidence = 0
		}
		if a.Confidence > 100 {
			a.Confidence = 100
		}
	}
	return sc.Apps, nil
}

// appsToEntries projects bundle apps onto the neutral repository rows.
func appsToEntries(serial int64, apps []BundleApp) []repository.AppIDCatalogEntry {
	out := make([]repository.AppIDCatalogEntry, len(apps))
	for i, a := range apps {
		out[i] = repository.AppIDCatalogEntry{
			Serial:       serial,
			AppID:        a.AppID,
			Category:     a.Category,
			SNISuffixes:  a.SNISuffixes,
			HostSuffixes: a.HostSuffixes,
			JA3:          a.JA3,
			BytePrefixes: a.BytePrefixes,
			Ports:        a.Ports,
			Transport:    a.Transport,
			Confidence:   a.Confidence,
		}
	}
	return out
}

// entriesToApps is the inverse of appsToEntries.
func entriesToApps(entries []repository.AppIDCatalogEntry) []BundleApp {
	out := make([]BundleApp, len(entries))
	for i, e := range entries {
		out[i] = BundleApp{
			AppID:        e.AppID,
			Category:     e.Category,
			SNISuffixes:  e.SNISuffixes,
			HostSuffixes: e.HostSuffixes,
			JA3:          e.JA3,
			BytePrefixes: e.BytePrefixes,
			Ports:        e.Ports,
			Transport:    e.Transport,
			Confidence:   e.Confidence,
		}
	}
	return out
}

// cloneApps deep-copies the app slice so normalize/sign mutations never
// touch the caller's data (notably the cached seed).
func cloneApps(in []BundleApp) []BundleApp {
	out := make([]BundleApp, len(in))
	for i, a := range in {
		a.SNISuffixes = append([]string(nil), a.SNISuffixes...)
		a.HostSuffixes = append([]string(nil), a.HostSuffixes...)
		a.JA3 = append([]string(nil), a.JA3...)
		a.BytePrefixes = append([]string(nil), a.BytePrefixes...)
		a.Ports = append([]int(nil), a.Ports...)
		out[i] = a
	}
	return out
}
