package residency

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// RegionResolver returns the designated data-residency region for a
// tenant. The production implementation reads tenants.region (the
// tenant's configured region IS its residency designation); a test
// supplies a static map. An empty region means residency is not
// configured for that tenant, and EnforceWrite treats it as
// unconstrained.
type RegionResolver interface {
	DesignatedRegion(ctx context.Context, tenantID uuid.UUID) (Region, error)
}

// RegionResolverFunc adapts a function to RegionResolver.
type RegionResolverFunc func(ctx context.Context, tenantID uuid.UUID) (Region, error)

// DesignatedRegion implements RegionResolver.
func (f RegionResolverFunc) DesignatedRegion(ctx context.Context, tenantID uuid.UUID) (Region, error) {
	return f(ctx, tenantID)
}

// TenantRegionResolver resolves a tenant's designated region from the
// tenant repository (the tenants.region column).
type TenantRegionResolver struct {
	tenants repository.TenantRepository
}

// NewTenantRegionResolver builds a RegionResolver backed by the tenant
// repository.
func NewTenantRegionResolver(tenants repository.TenantRepository) *TenantRegionResolver {
	return &TenantRegionResolver{tenants: tenants}
}

// DesignatedRegion implements RegionResolver.
func (r *TenantRegionResolver) DesignatedRegion(ctx context.Context, tenantID uuid.UUID) (Region, error) {
	t, err := r.tenants.Get(ctx, tenantID)
	if err != nil {
		return "", err
	}
	return Region(t.Region), nil
}

// Service enforces data residency for tenant write paths. It resolves
// each tenant's designated region, applies the fail-closed
// EnforceWrite rule, and durably records every rejection so the
// enforcement is auditable.
type Service struct {
	resolver RegionResolver
	audit    repository.ResidencyAuditRepository
	logger   *slog.Logger
}

// NewService constructs a residency Service. resolver is required;
// audit may be nil (rejections are then only logged, not persisted),
// which is useful in tests and in deployments without the
// residency_audit table.
func NewService(resolver RegionResolver, audit repository.ResidencyAuditRepository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{resolver: resolver, audit: audit, logger: logger}
}

// Check is the fail-closed residency gate for a write. It returns nil
// when the write to targetRegion is permitted for the tenant, and an
// error wrapping ErrResidencyViolation when it is not. A rejection is
// recorded to the audit trail (best-effort: a recording failure is
// logged but does not mask the residency decision).
//
// A resolver error is itself fail-closed: if the tenant's designated
// region cannot be determined, the write is rejected rather than
// allowed.
func (s *Service) Check(ctx context.Context, tenantID uuid.UUID, plane Plane, targetRegion Region) error {
	designated, err := s.resolver.DesignatedRegion(ctx, tenantID)
	if err != nil {
		return err
	}
	if verr := EnforceWrite(designated, targetRegion, plane); verr != nil {
		s.record(ctx, tenantID, plane, Normalize(designated), Normalize(targetRegion), verr)
		return verr
	}
	return nil
}

// record persists a rejection. Best-effort: the residency decision has
// already been made, so a failure to write the audit row must not turn
// a denial into something the caller mishandles — it is logged and
// swallowed.
func (s *Service) record(ctx context.Context, tenantID uuid.UUID, plane Plane, designated, target Region, verr error) {
	if s.audit == nil {
		return
	}
	_, err := s.audit.Record(ctx, tenantID, repository.ResidencyAuditEntry{
		Plane:            string(plane),
		DesignatedRegion: string(designated),
		AttemptedRegion:  string(target),
		Detail:           verr.Error(),
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		s.logger.WarnContext(ctx, "residency: failed to record rejection",
			"tenant_id", tenantID, "plane", plane, "error", err)
	}
}

// Guard adapts the residency Service to the narrow interface a data
// plane (e.g. the telemetry S3 archiver) depends on, binding a fixed
// plane and the region the sink writes to. This keeps the data-plane
// package free of any residency-service or repository import — it
// depends only on a single-method interface it defines itself.
type Guard struct {
	svc        *Service
	plane      Plane
	sinkRegion Region
}

// NewGuard binds a Service to a specific plane and the region its sink
// writes to (e.g. the AWS region of the cold-archive bucket).
func NewGuard(svc *Service, plane Plane, sinkRegion Region) *Guard {
	return &Guard{svc: svc, plane: plane, sinkRegion: sinkRegion}
}

// Check reports whether the tenant's data may be written to this
// guard's sink region, fail-closed.
func (g *Guard) Check(ctx context.Context, tenantID uuid.UUID) error {
	return g.svc.Check(ctx, tenantID, g.plane, g.sinkRegion)
}
