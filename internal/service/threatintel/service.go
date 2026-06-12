package threatintel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRefreshInterval is the cadence the managed feed loop refreshes
// on when the operator does not override it. One hour matches the
// hourly default of the IOC aggregator (internal/service/ai) and is the
// right order of magnitude for DNS reputation / category feeds, which
// publish on the scale of hours, not seconds.
const DefaultRefreshInterval = time.Hour

// DefaultSubject is the NATS subject the signed bundle is published on
// when the operator does not override it. It sits on the policy stream
// (`sng.*.policy.>`) under a reserved "platform" pseudo-tenant token
// because the feed is platform-global, not tenant-scoped, reusing the
// existing signed-bundle distribution stream rather than introducing a
// new one.
const DefaultSubject = "sng.platform.policy.threatintel.dns.v1"

// BundlePublisher distributes a signed bundle. The production
// implementation adapts the JetStream *nats.Publisher; tests inject an
// in-memory fake. Decoupling via this interface keeps the package free
// of a hard NATS dependency and lets the refresh path be unit-tested
// without a broker.
type BundlePublisher interface {
	// PublishBundle sends data on subject. It must be safe for
	// concurrent use and should apply its own retry / dedup policy.
	PublishBundle(ctx context.Context, subject string, data []byte) error
}

// Service is the managed threat-intel feed pipeline: it fetches each
// configured source, assembles + signs a FeedBundle, and distributes
// the signed envelope. It is leader-gated by the caller
// (cmd/sng-control wires Run under elector.RunIfLeader) so exactly one
// replica produces one signed bundle per interval in a multi-replica
// deployment.
type Service struct {
	sources   []Source
	signer    *Signer
	keyID     string
	publisher BundlePublisher
	subject   string
	logger    *slog.Logger
	now       func() time.Time

	// lastGood caches the most recent successful parse per source so a
	// transient upstream failure degrades to last-known-good rather
	// than dropping that source's domains from the next bundle (which
	// would silently UN-block previously-blocked traffic — a fail-open
	// regression). Guarded by mu.
	mu       sync.Mutex
	lastGood map[string]sourceState

	// lastSerial is the serial of the most recently published bundle.
	// Monotonic: each refresh derives a serial of max(now, lastSerial+1)
	// so a clock skew or two refreshes within the same second still
	// advance it, and the consumer's "ignore lower serial" rule holds.
	lastSerial atomic.Int64

	// last holds the most recently published envelope for status /
	// readiness re-publish. nil until the first successful publish.
	last atomic.Pointer[SignedBundle]

	metrics metrics
}

// sourceState is a cached successful fetch for one source.
type sourceState struct {
	domains   []string
	fetchedAt time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithLogger sets the logger. Defaults to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithSubject overrides the publish subject. Empty keeps DefaultSubject.
func WithSubject(subject string) Option {
	return func(s *Service) {
		if subject != "" {
			s.subject = subject
		}
	}
}

// WithKeyID sets the signing key identifier stamped into the envelope
// so the consumer can select the matching pinned verifying key.
func WithKeyID(keyID string) Option {
	return func(s *Service) { s.keyID = keyID }
}

// withClock overrides the clock (tests).
func withClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// NewService constructs the pipeline. signer and publisher are
// required; sources may be empty (the loop then runs but publishes an
// empty bundle only on its first refresh and otherwise no-ops, matching
// the "configured upstream or safe no-op" posture).
func NewService(sources []Source, signer *Signer, publisher BundlePublisher, opts ...Option) (*Service, error) {
	if signer == nil {
		return nil, errors.New("threatintel: nil signer")
	}
	if publisher == nil {
		return nil, errors.New("threatintel: nil publisher")
	}
	if err := validateSources(sources); err != nil {
		return nil, err
	}
	s := &Service{
		sources:   sources,
		signer:    signer,
		publisher: publisher,
		subject:   DefaultSubject,
		logger:    slog.Default(),
		now:       time.Now,
		lastGood:  make(map[string]sourceState, len(sources)),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// validateSources rejects a misconfigured source set (duplicate or
// empty names, category sources without a category, nil fetchers) at
// construction so the failure surfaces at boot, not mid-refresh.
func validateSources(sources []Source) error {
	seen := make(map[string]struct{}, len(sources))
	for i, src := range sources {
		if src.Name == "" {
			return fmt.Errorf("threatintel: source %d has empty name", i)
		}
		if _, dup := seen[src.Name]; dup {
			return fmt.Errorf("threatintel: duplicate source name %q", src.Name)
		}
		seen[src.Name] = struct{}{}
		if src.Fetcher == nil {
			return fmt.Errorf("threatintel: source %q has nil fetcher", src.Name)
		}
		if src.Kind == KindCategory && src.Category == "" {
			return fmt.Errorf("threatintel: category source %q has empty category", src.Name)
		}
	}
	return nil
}

// RefreshResult summarizes one refresh for telemetry / tests.
type RefreshResult struct {
	Serial         int64
	BundleBytes    int
	ReputationSize int
	CategorySizes  map[string]int
	SourcesOK      int
	SourcesFailed  int
	// Published is false when the refresh produced no usable data and
	// therefore did not publish (so the consumer keeps last-known-good).
	Published bool
}

// RefreshOnce fetches every source, assembles + signs a bundle, and
// publishes it. Per-source fetch / parse failures are logged and the
// source falls back to its last-known-good snapshot rather than
// dropping its domains. The bundle is published only when at least one
// source contributed data (live or cached); a refresh in which every
// source has failed and none has ever succeeded does NOT publish an
// empty bundle, so the edge is never wiped to a fail-open state by a
// total upstream outage.
func (s *Service) RefreshOnce(ctx context.Context) (RefreshResult, error) {
	s.metrics.recordRefresh()
	serial := s.nextSerial()
	bundle := newBundle(serial, s.now())

	var okCount, failCount int
	contributed := false
	for _, src := range s.sources {
		domains, fresh, err := s.fetchSource(ctx, src)
		if err != nil {
			failCount++
			s.metrics.recordFetch(src.Name, false, s.now())
			s.logger.Warn("threatintel: source refresh failed; using last-known-good",
				slog.String("source", src.Name),
				slog.String("kind", src.Kind.String()),
				slog.Int("cached_domains", len(domains)),
				slog.Any("error", err))
		} else {
			okCount++
			s.metrics.recordFetch(src.Name, true, s.now())
			if fresh {
				s.logger.Info("threatintel: source refreshed",
					slog.String("source", src.Name),
					slog.String("kind", src.Kind.String()),
					slog.Int("domains", len(domains)))
			}
		}
		if len(domains) == 0 {
			continue
		}
		contributed = true
		switch src.Kind {
		case KindReputation:
			bundle.Reputation = append(bundle.Reputation, domains...)
		case KindCategory:
			bundle.Categories[src.Category] = append(bundle.Categories[src.Category], domains...)
		}
	}

	if !contributed {
		s.logger.Warn("threatintel: refresh produced no data from any source; not publishing (edge keeps last-known-good)",
			slog.Int("sources_failed", failCount))
		return RefreshResult{Serial: serial, SourcesFailed: failCount}, errAllSourcesEmpty
	}

	signed, err := bundle.Sign(s.signer, s.keyID)
	if err != nil {
		return RefreshResult{}, err
	}
	data, err := signed.Marshal()
	if err != nil {
		return RefreshResult{}, err
	}
	if err := s.publisher.PublishBundle(ctx, s.subject, data); err != nil {
		return RefreshResult{}, fmt.Errorf("threatintel: publish bundle: %w", err)
	}

	s.last.Store(&signed)
	repSize, catSizes := bundle.Counts()
	s.metrics.recordPublish(serial, len(data), s.now())
	s.logger.Info("threatintel: published signed feed bundle",
		slog.Int64("serial", serial),
		slog.String("subject", s.subject),
		slog.Int("bytes", len(data)),
		slog.Int("reputation", repSize),
		slog.Int("categories", len(catSizes)),
		slog.Int("sources_ok", okCount),
		slog.Int("sources_failed", failCount))

	return RefreshResult{
		Serial:         serial,
		BundleBytes:    len(data),
		ReputationSize: repSize,
		CategorySizes:  catSizes,
		SourcesOK:      okCount,
		SourcesFailed:  failCount,
		Published:      true,
	}, nil
}

// errAllSourcesEmpty signals a refresh that contributed no data and so
// did not publish. Callers (the Run loop) treat it as a soft skip, not
// a hard error worth alarming on every cycle during a long outage.
var errAllSourcesEmpty = errors.New("threatintel: no source contributed data")

// fetchSource fetches and parses one source, updating its
// last-known-good cache on success. On failure it returns the cached
// domains (possibly empty) with the underlying error and fresh=false so
// the caller can fall back without dropping the source. fresh=true
// indicates a live successful fetch.
func (s *Service) fetchSource(ctx context.Context, src Source) (domains []string, fresh bool, err error) {
	raw, ferr := src.Fetcher.Fetch(ctx)
	if ferr != nil {
		return s.cachedDomains(src.Name), false, ferr
	}
	parsed := parseDomainList(raw)
	if len(parsed) == 0 {
		// A successful fetch that parses to nothing is suspicious (empty
		// body, wrong endpoint, format change). Keep last-known-good
		// rather than letting an empty parse erase the source.
		cached := s.cachedDomains(src.Name)
		if len(cached) > 0 {
			return cached, false, fmt.Errorf("threatintel: source %q parsed to zero domains", src.Name)
		}
		return nil, true, nil
	}
	s.storeCached(src.Name, parsed)
	return parsed, true, nil
}

func (s *Service) cachedDomains(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastGood[name].domains
}

func (s *Service) storeCached(name string, domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGood[name] = sourceState{domains: domains, fetchedAt: s.now().UTC()}
}

// nextSerial returns a strictly increasing generation serial. It uses
// the producer wall clock (unix seconds) but guarantees monotonicity
// even across clock skew or sub-second refreshes by advancing past the
// last serial when necessary.
func (s *Service) nextSerial() int64 {
	for {
		prev := s.lastSerial.Load()
		next := s.now().UTC().Unix()
		if next <= prev {
			next = prev + 1
		}
		if s.lastSerial.CompareAndSwap(prev, next) {
			return next
		}
	}
}

// LastBundle returns the most recently published signed envelope, or
// nil if nothing has been published yet. Used for status surfaces and a
// future readiness re-publish.
func (s *Service) LastBundle() *SignedBundle {
	return s.last.Load()
}

// Stats returns a snapshot of pipeline telemetry.
func (s *Service) Stats() Stats {
	return s.metrics.snapshot()
}

// Run drives the refresh loop until ctx is cancelled. It performs an
// immediate refresh on entry (so a freshly-elected leader publishes
// without waiting a full interval) and then refreshes on the ticker.
// interval <= 0 applies DefaultRefreshInterval. Run blocks; the caller
// launches it in its own goroutine under elector.RunIfLeader.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	s.logger.Info("threatintel: managed feed loop started",
		slog.Duration("interval", interval),
		slog.String("subject", s.subject),
		slog.Int("sources", len(s.sources)))

	// Immediate warm-up refresh; errAllSourcesEmpty is a soft skip.
	if _, err := s.RefreshOnce(ctx); err != nil && !errors.Is(err, errAllSourcesEmpty) {
		s.logger.Error("threatintel: initial refresh failed", slog.Any("error", err))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("threatintel: managed feed loop stopped")
			return
		case <-ticker.C:
			if _, err := s.RefreshOnce(ctx); err != nil && !errors.Is(err, errAllSourcesEmpty) {
				s.logger.Error("threatintel: scheduled refresh failed", slog.Any("error", err))
			}
		}
	}
}
