package threatintel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// IPSRuleProvider yields the current Suricata rule text compiled from
// the in-process IOC store. It is injected (rather than importing the
// ai package here) so this producer stays a thin signing/publishing
// shell over whatever rule compiler the caller wires in — mirroring
// how the DNS pipeline injects its in-process IOC domains via
// SnapshotFetcher. Total is the rule count, carried for telemetry.
type IPSRuleProvider func() (rulesText string, total int)

// IPSRuleService signs and publishes the threat-intel Suricata rule
// bundle the edge's sng-ips crate verifies, stages and hot-swaps. It
// is the IPS-tier sibling of Service (the DNS feed pipeline): same
// Ed25519 signing, same leader-gated publish cadence, distinct
// subject and body format (the MessagePack IpsRuleBundleClaims the
// edge expects).
//
// Unlike Service it has no upstream fetch / last-known-good machinery:
// its single input is the in-process IOC store snapshot, which is
// authoritative (not a flaky network fetch), so an empty rule set is
// a legitimate state to publish (it drains stale rules) rather than a
// failure to fall back from.
type IPSRuleService struct {
	provider  IPSRuleProvider
	signer    *Signer
	compiler  string
	publisher BundlePublisher
	subject   string
	logger    *slog.Logger
	now       func() time.Time

	// version is the monotonically increasing bundle revision. The
	// edge rejects any bundle whose version is <= the installed one,
	// so this must never regress; derived like the DNS serial from
	// the wall clock but advanced past the last value on skew.
	version atomic.Uint64
	// last holds the most recently published envelope for status.
	last atomic.Pointer[SignedIPSRuleBundle]
}

// IPSRuleOption configures an IPSRuleService.
type IPSRuleServiceOption func(*IPSRuleService)

// WithIPSLogger sets the logger. Defaults to slog.Default().
func WithIPSLogger(logger *slog.Logger) IPSRuleServiceOption {
	return func(s *IPSRuleService) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithIPSSubject overrides the publish subject. Empty keeps
// DefaultIPSRuleSubject.
func WithIPSSubject(subject string) IPSRuleServiceOption {
	return func(s *IPSRuleService) {
		if subject != "" {
			s.subject = subject
		}
	}
}

// WithIPSCompiler sets the free-form compiler id stamped into the
// bundle body (`comp`). Empty keeps the default.
func WithIPSCompiler(id string) IPSRuleServiceOption {
	return func(s *IPSRuleService) {
		if id != "" {
			s.compiler = id
		}
	}
}

// withIPSClock overrides the clock (tests).
func withIPSClock(now func() time.Time) IPSRuleServiceOption {
	return func(s *IPSRuleService) {
		if now != nil {
			s.now = now
		}
	}
}

const defaultIPSCompilerID = "sng-control/threat-intel"

// NewIPSRuleService constructs the producer. provider, signer and
// publisher are required.
func NewIPSRuleService(provider IPSRuleProvider, signer *Signer, publisher BundlePublisher, opts ...IPSRuleServiceOption) (*IPSRuleService, error) {
	if provider == nil {
		return nil, errors.New("threatintel: nil ips rule provider")
	}
	if signer == nil {
		return nil, errors.New("threatintel: nil signer")
	}
	if publisher == nil {
		return nil, errors.New("threatintel: nil publisher")
	}
	s := &IPSRuleService{
		provider:  provider,
		signer:    signer,
		compiler:  defaultIPSCompilerID,
		publisher: publisher,
		subject:   DefaultIPSRuleSubject,
		logger:    slog.Default(),
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// IPSRuleRefreshResult summarizes one publish for telemetry / tests.
type IPSRuleRefreshResult struct {
	Version     uint64
	BundleBytes int
	RuleCount   int
}

// nextVersion returns a strictly increasing revision, monotonic even
// across clock skew or sub-second refreshes (see Service.nextSerial).
func (s *IPSRuleService) nextVersion() uint64 {
	for {
		prev := s.version.Load()
		next := uint64(s.now().UTC().Unix())
		if next <= prev {
			next = prev + 1
		}
		if s.version.CompareAndSwap(prev, next) {
			return next
		}
	}
}

// RefreshOnce compiles the current rule set, signs it, and publishes
// the signed bundle. An empty rule set is published (it drains the
// edge to "no threat-intel rules") rather than skipped, because the
// in-process store snapshot is authoritative.
func (s *IPSRuleService) RefreshOnce(ctx context.Context) (IPSRuleRefreshResult, error) {
	rulesText, total := s.provider()
	version := s.nextVersion()
	claims := IPSRuleBundleClaims{
		SchemaVersion: IPSRuleSchemaVersion,
		Version:       version,
		Compiler:      s.compiler,
		RulesText:     rulesText,
		Source:        IPSRuleSourceCustomOrg,
	}
	signed, err := s.signer.SignIPSRuleBundle(claims)
	if err != nil {
		return IPSRuleRefreshResult{}, err
	}
	data, err := signed.Marshal()
	if err != nil {
		return IPSRuleRefreshResult{}, err
	}
	if err := s.publisher.PublishBundle(ctx, s.subject, data); err != nil {
		return IPSRuleRefreshResult{}, fmt.Errorf("threatintel: publish ips rule bundle: %w", err)
	}
	s.last.Store(&signed)
	s.logger.Info("threatintel: published signed ips rule bundle",
		slog.Uint64("version", version),
		slog.String("subject", s.subject),
		slog.Int("bytes", len(data)),
		slog.Int("rules", total))
	return IPSRuleRefreshResult{Version: version, BundleBytes: len(data), RuleCount: total}, nil
}

// LastBundle returns the most recently published envelope, or nil.
func (s *IPSRuleService) LastBundle() *SignedIPSRuleBundle {
	return s.last.Load()
}

// Run drives the publish loop until ctx is cancelled, publishing
// immediately on entry then on the ticker. interval <= 0 applies
// DefaultRefreshInterval. Run blocks; the caller launches it under
// elector.RunIfLeader.
func (s *IPSRuleService) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	s.logger.Info("threatintel: ips rule producer loop started",
		slog.Duration("interval", interval),
		slog.String("subject", s.subject))

	if _, err := s.RefreshOnce(ctx); err != nil {
		s.logger.Error("threatintel: initial ips rule publish failed", slog.Any("error", err))
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("threatintel: ips rule producer loop stopped")
			return
		case <-ticker.C:
			if _, err := s.RefreshOnce(ctx); err != nil {
				s.logger.Error("threatintel: scheduled ips rule publish failed", slog.Any("error", err))
			}
		}
	}
}
