// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultHighWaterFraction is the utilization at or above which a PoP
// is considered overloaded: it is excluded from NEW assignments and
// becomes a rebalance candidate. 0.85 leaves headroom for the
// in-flight connections a newly-steered tenant brings before its own
// beacon reflects the added load.
const DefaultHighWaterFraction = 0.85

// DefaultRefreshInterval is how often the registry reloads the fleet
// from Postgres when Service.Run drives the loop.
const DefaultRefreshInterval = 30 * time.Second

// maxBeaconFutureSkew bounds how far ahead of the control plane's
// clock a beacon's reported_at may be before we stop trusting it.
// Staleness is judged by clock().Sub(reported_at) <= healthTTL, so a
// beacon dated far in the future (a mis-set or hostile edge clock)
// would make that difference negative and keep the PoP "healthy"
// forever; because the registry keeps the latest reading by
// reported_at, such a beacon would also shadow every subsequent
// honest one. A minute comfortably covers real NTP skew between an
// edge and the control plane; anything beyond it is clamped to
// server time so the PoP still ages out normally.
const maxBeaconFutureSkew = time.Minute

// RegionLocator maps a client IP to a coarse geographic region (e.g.
// "us-east", "eu-west") used to bias PoP selection toward the
// client's locale. Production wires a GeoIP-backed implementation;
// tests use StaticRegionLocator. A nil locator (or one that returns
// ok=false) makes AssignPoP fall back to purely load-based selection,
// leaving fine-grained latency steering to the GeoDNS tier.
type RegionLocator interface {
	LocateRegion(ip netip.Addr) (region string, ok bool)
}

// Service is the control-plane PoP manager: registry + health +
// capacity + tenant assignments.
type Service struct {
	store         Store
	registry      *Registry
	locator       RegionLocator
	tenantRegions TenantRegionResolver
	logger        *slog.Logger
	highWater     float64
	autoscale     AutoscaleConfig
	clock         func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithLogger sets the service logger. A nil logger is ignored.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithRegionLocator wires a GeoIP-style locator for locale-aware
// assignment.
func WithRegionLocator(loc RegionLocator) Option {
	return func(s *Service) { s.locator = loc }
}

// WithTenantRegionResolver wires the resolver that maps a tenant to its
// coarse region marker, enabling tenant-region-biased PoP selection. A
// nil resolver (the default) leaves selection on client-IP region and
// load alone, preserving the pre-2B behaviour.
func WithTenantRegionResolver(r TenantRegionResolver) Option {
	return func(s *Service) { s.tenantRegions = r }
}

// WithAutoscaleConfig overrides the connected-tenant-per-PoP target
// band used by PlanRegionCapacity. The zero value keeps the package
// default; band invariants are re-established by withDefaults at plan
// time, so a partial override is safe.
func WithAutoscaleConfig(c AutoscaleConfig) Option {
	return func(s *Service) { s.autoscale = c }
}

// WithHighWaterFraction overrides the overload threshold. Values
// outside (0, 1] are ignored.
func WithHighWaterFraction(f float64) Option {
	return func(s *Service) {
		if f > 0 && f <= 1 {
			s.highWater = f
		}
	}
}

func withServiceClock(clock func() time.Time) Option {
	return func(s *Service) {
		if clock != nil {
			s.clock = clock
		}
	}
}

// NewService builds a PoP service over store and registry. registry
// must share store's data (typically NewRegistry(store)).
func NewService(store Store, registry *Registry, opts ...Option) *Service {
	s := &Service{
		store:     store,
		registry:  registry,
		logger:    slog.Default(),
		highWater: DefaultHighWaterFraction,
		clock:     func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Registry exposes the in-memory registry (for the NATS beacon
// handler and tests).
func (s *Service) Registry() *Registry { return s.registry }

// --- PoP registration + listing ---

// RegisterPoP validates and persists a new PoP, then refreshes the
// registry so the new location is immediately assignable.
func (s *Service) RegisterPoP(ctx context.Context, p PoP) (PoP, error) {
	if p.Region == "" || p.DNSName == "" {
		return PoP{}, fmt.Errorf("%w: region and dns_name are required", repository.ErrInvalidArgument)
	}
	if !p.Provider.Valid() {
		return PoP{}, fmt.Errorf("%w: provider %q must be aws|gcp|azure", repository.ErrInvalidArgument, p.Provider)
	}
	if !p.CapacityTier.Valid() {
		return PoP{}, fmt.Errorf("%w: capacity_tier %q must be small|medium|large", repository.ErrInvalidArgument, p.CapacityTier)
	}
	if !validIP(p.AnycastIP) {
		return PoP{}, fmt.Errorf("%w: anycast_ip %q is not a valid IP address", repository.ErrInvalidArgument, p.AnycastIP)
	}
	created, err := s.store.CreatePoP(ctx, p)
	if err != nil {
		return PoP{}, err
	}
	if err := s.registry.Refresh(ctx); err != nil {
		// The row is committed; a stale registry self-heals on the next
		// periodic refresh, so surface as a warning, not a failure.
		s.logger.Warn("pop: registry refresh after register failed",
			slog.String("pop_id", created.ID.String()), slog.Any("error", err))
	}
	return created, nil
}

// ListAvailable returns the enabled PoPs for the public bootstrap
// endpoint. Served from the in-memory registry (no DB hit on the hot
// bootstrap path).
func (s *Service) ListAvailable() []PoP {
	return s.registry.Available()
}

// PoPHealthView is the admin health projection: the PoP plus its
// latest beacon and derived state.
type PoPHealthView struct {
	PoP        PoP
	Health     *Health
	Healthy    bool
	Overloaded bool
}

// HealthView returns the admin health view for a PoP.
func (s *Service) HealthView(ctx context.Context, popID uuid.UUID) (PoPHealthView, error) {
	p, ok := s.registry.Get(popID)
	if !ok {
		// Fall back to the store in case the registry has not refreshed
		// since the PoP was created out-of-band.
		var err error
		p, err = s.store.GetPoP(ctx, popID)
		if err != nil {
			return PoPHealthView{}, err
		}
	}
	view := PoPHealthView{PoP: p}
	if h, ok := s.registry.Health(popID); ok {
		hCopy := h
		view.Health = &hCopy
		view.Healthy = s.clock().Sub(h.ReportedAt) <= s.registry.healthTTL
		view.Overloaded = utilization(p, h, true) >= s.highWater
	}
	return view, nil
}

// --- health ingestion ---

// IngestHealth persists a beacon and folds it into the registry. The
// NATS subscriber calls this for every `sng.pop.{id}.health` message.
func (s *Service) IngestHealth(ctx context.Context, h Health) error {
	if h.PoPID == uuid.Nil {
		return fmt.Errorf("%w: beacon missing pop_id", repository.ErrInvalidArgument)
	}
	// Stamp server time when the edge omitted the timestamp, and refuse
	// to trust a reported_at that is implausibly far in the future
	// (clamp it to now) so a skewed or hostile edge clock cannot pin a
	// PoP as permanently healthy or shadow later honest beacons.
	now := s.clock()
	if h.ReportedAt.IsZero() || h.ReportedAt.After(now.Add(maxBeaconFutureSkew)) {
		h.ReportedAt = now
	}
	if err := s.store.RecordHealth(ctx, h); err != nil {
		return err
	}
	s.registry.ApplyHealth(h)
	return nil
}

// --- assignment ---

// AssignPoP returns the PoP that should serve tenantID for a client
// connecting from clientIP, GeoDNS-style: the lowest-latency healthy
// PoP. The choice is sticky — once a tenant is homed to a PoP the same
// PoP is returned on subsequent calls (so a tenant's flows stay on one
// inspection point) unless that PoP is no longer a valid candidate, in
// which case the tenant is re-homed and the assignment updated.
//
// "Lowest-latency" is approximated as: prefer PoPs in the client's
// region (when a RegionLocator resolves one), then pick the
// least-loaded healthy, enabled, non-overloaded PoP. True per-client
// latency steering is handled at the DNS tier by geodns.go.
func (s *Service) AssignPoP(ctx context.Context, tenantID uuid.UUID, clientIP string) (PoP, error) {
	if tenantID == uuid.Nil {
		return PoP{}, fmt.Errorf("%w: tenant_id is required", repository.ErrInvalidArgument)
	}
	var clientAddr netip.Addr
	if clientIP != "" {
		addr, err := netip.ParseAddr(clientIP)
		if err != nil {
			return PoP{}, fmt.Errorf("%w: client_ip %q is not a valid IP address", repository.ErrInvalidArgument, clientIP)
		}
		clientAddr = addr
	}

	// Honour an existing sticky assignment when it is still serviceable.
	if existing, err := s.store.GetAssignment(ctx, tenantID); err == nil {
		if p, ok := s.registry.Get(existing.PoPID); ok && p.Enabled {
			// Operator overrides are always honoured (even if currently
			// hot); auto-assignments stick only while still healthy.
			if existing.Override || s.registry.isHealthy(s.registry.current(), p.ID) {
				return p, nil
			}
		}
	} else if !errors.Is(err, repository.ErrNotFound) {
		return PoP{}, err
	}

	best, err := s.pickBest(clientAddr, s.preferredRegionSet(ctx, tenantID))
	if err != nil {
		return PoP{}, err
	}
	if _, err := s.store.UpsertAssignment(ctx, Assignment{TenantID: tenantID, PoPID: best.ID}); err != nil {
		return PoP{}, err
	}
	return best, nil
}

// candidate pairs a PoP with its current utilization for ranking.
type candidate struct {
	pop  PoP
	util float64
}

// pickBest selects the lowest-latency healthy PoP for a client,
// biased first to the tenant's region group (when groupRegions is
// non-nil) and then to the client's region (when a locator resolves
// one). Returns repository.ErrResourceExhausted when no PoP can take
// new load.
//
// Candidate-pool precedence (first non-empty wins):
//
//	with a tenant region group:
//	  1. in-group AND in client-region   (closest, residency-aligned)
//	  2. in-group                        (residency-aligned)
//	  3. global                          (availability fallback)
//	without a tenant region group (pre-2B behaviour):
//	  1. in client-region
//	  2. global
//
// The group is a strong preference, not a hard pin: when the tenant's
// region group is exhausted we fall back to the global least-loaded
// PoP and log it, so a regional outage degrades latency rather than
// stranding the tenant. Hard data-residency pinning is an operator
// override assignment, not this path.
func (s *Service) pickBest(clientAddr netip.Addr, groupRegions map[string]bool) (PoP, error) {
	snap := s.registry.current()
	var preferredRegion string
	var haveRegion bool
	if s.locator != nil && clientAddr.IsValid() {
		preferredRegion, haveRegion = s.locator.LocateRegion(clientAddr)
	}

	var inGroupInRegion, inGroup, inRegion, global []candidate
	for _, p := range snap.pops {
		if !p.Enabled {
			continue
		}
		if !s.registry.isHealthy(snap, p.ID) {
			continue
		}
		h := snap.health[p.ID]
		u := utilization(p, h, true)
		if u >= s.highWater {
			continue // overloaded — leave headroom
		}
		c := candidate{pop: p, util: u}
		global = append(global, c)
		clientRegionMatch := haveRegion && p.Region == preferredRegion
		if clientRegionMatch {
			inRegion = append(inRegion, c)
		}
		if groupRegions != nil && groupRegions[p.Region] {
			inGroup = append(inGroup, c)
			if clientRegionMatch {
				inGroupInRegion = append(inGroupInRegion, c)
			}
		}
	}

	pool := selectPool(groupRegions != nil, inGroupInRegion, inGroup, inRegion, global)
	if len(pool) == 0 {
		return PoP{}, fmt.Errorf("%w: no healthy PoP with available capacity", repository.ErrResourceExhausted)
	}
	if groupRegions != nil && len(inGroup) == 0 {
		s.logger.Warn("pop: tenant region group exhausted; falling back to global least-loaded PoP")
	}
	return leastLoaded(pool), nil
}

// selectPool applies the candidate-pool precedence described on
// pickBest and returns the first non-empty tier.
func selectPool(haveGroup bool, inGroupInRegion, inGroup, inRegion, global []candidate) []candidate {
	if haveGroup {
		switch {
		case len(inGroupInRegion) > 0:
			return inGroupInRegion
		case len(inGroup) > 0:
			return inGroup
		default:
			return global
		}
	}
	if len(inRegion) > 0 {
		return inRegion
	}
	return global
}

// leastLoaded returns the lowest-utilization candidate, ties broken by
// id for determinism. The input must be non-empty.
func leastLoaded(pool []candidate) PoP {
	sort.Slice(pool, func(i, j int) bool {
		if pool[i].util != pool[j].util {
			return pool[i].util < pool[j].util
		}
		return pool[i].pop.ID.String() < pool[j].pop.ID.String()
	})
	return pool[0].pop
}

// SetAssignment pins tenantID to popID (operator override of the
// auto-assignment). The PoP must exist and be enabled.
func (s *Service) SetAssignment(ctx context.Context, tenantID, popID uuid.UUID, override bool) (Assignment, error) {
	if tenantID == uuid.Nil || popID == uuid.Nil {
		return Assignment{}, fmt.Errorf("%w: tenant_id and pop_id are required", repository.ErrInvalidArgument)
	}
	p, ok := s.registry.Get(popID)
	if !ok {
		var err error
		if p, err = s.store.GetPoP(ctx, popID); err != nil {
			return Assignment{}, err
		}
	}
	if !p.Enabled {
		return Assignment{}, fmt.Errorf("%w: pop %s is disabled", repository.ErrInvalidArgument, popID)
	}
	return s.store.UpsertAssignment(ctx, Assignment{TenantID: tenantID, PoPID: popID, Override: override})
}

// --- capacity management / rebalancing ---

// OverloadedPoPs returns the enabled PoPs whose latest beacon is at or
// above the high-water mark — the PoPs the rebalancer should drain.
func (s *Service) OverloadedPoPs() []PoP {
	snap := s.registry.current()
	var out []PoP
	for _, p := range snap.pops {
		if !p.Enabled {
			continue
		}
		h, ok := snap.health[p.ID]
		if !ok {
			continue
		}
		if utilization(p, h, true) >= s.highWater {
			out = append(out, p)
		}
	}
	return out
}

// Rebalance moves non-override tenants off every overloaded PoP onto
// the least-loaded healthy alternative. Runs under the system role
// (cross-tenant) and is intended to be driven on the leader replica.
// Returns the number of tenants moved.
func (s *Service) Rebalance(ctx context.Context) (int, error) {
	overloaded := s.OverloadedPoPs()
	moved := 0
	for _, hot := range overloaded {
		assignments, err := s.store.ListAssignmentsByPoP(ctx, hot.ID)
		if err != nil {
			return moved, err
		}
		for _, a := range assignments {
			if a.Override {
				continue // operator-pinned — never auto-move
			}
			target, err := s.pickBestExcluding(hot.ID)
			if err != nil {
				// No alternative has capacity; stop trying this round.
				s.logger.Warn("pop: rebalance found no target",
					slog.String("from_pop", hot.ID.String()), slog.Any("error", err))
				break
			}
			if _, err := s.store.UpsertAssignment(ctx, Assignment{TenantID: a.TenantID, PoPID: target.ID}); err != nil {
				return moved, err
			}
			moved++
			s.logger.Info("pop: rebalanced tenant",
				slog.String("tenant_id", a.TenantID.String()),
				slog.String("from_pop", hot.ID.String()),
				slog.String("to_pop", target.ID.String()))
		}
	}
	return moved, nil
}

// pickBestExcluding is pickBest with no region bias and one PoP
// removed from the candidate set (the overloaded source).
func (s *Service) pickBestExcluding(exclude uuid.UUID) (PoP, error) {
	snap := s.registry.current()
	var pool []candidate
	for _, p := range snap.pops {
		if p.ID == exclude || !p.Enabled || !s.registry.isHealthy(snap, p.ID) {
			continue
		}
		u := utilization(p, snap.health[p.ID], true)
		if u >= s.highWater {
			continue
		}
		pool = append(pool, candidate{pop: p, util: u})
	}
	if len(pool) == 0 {
		return PoP{}, fmt.Errorf("%w: no alternative PoP with capacity", repository.ErrResourceExhausted)
	}
	sort.Slice(pool, func(i, j int) bool {
		if pool[i].util != pool[j].util {
			return pool[i].util < pool[j].util
		}
		return pool[i].pop.ID.String() < pool[j].pop.ID.String()
	})
	return pool[0].pop, nil
}

// --- background loop ---

// Run drives the periodic registry refresh until ctx is cancelled. It
// does an immediate refresh on entry so the registry is warm before
// the first request, then ticks every interval. Intended to run on
// every replica (each keeps its own lock-free registry).
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	if err := s.registry.Refresh(ctx); err != nil && ctx.Err() == nil {
		s.logger.Warn("pop: initial registry refresh failed", slog.Any("error", err))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.registry.Refresh(ctx); err != nil && ctx.Err() == nil {
				s.logger.Warn("pop: registry refresh failed", slog.Any("error", err))
			}
		}
	}
}
