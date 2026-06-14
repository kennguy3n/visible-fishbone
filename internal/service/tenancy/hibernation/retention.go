package hibernation

import (
	"context"

	"github.com/google/uuid"
)

// DefaultHibernatedRetentionDays is the ClickHouse retention a
// hibernated tenant's rows are written with. It is deliberately tiny:
// the ClickHouse writer clamps every resolver result up to its own
// MinRetentionDays floor (30 days), so this drives a parked tenant to
// the most aggressive retention the platform allows, ageing its hot
// partitions into the S3 cold tier as fast as the compliance floor
// permits — never below it. The cold tier retains the data for
// audit/compliance reads; nothing is deleted early.
const DefaultHibernatedRetentionDays = 1

// daysResolver is the structural subset of
// clickhouse.RetentionResolver the [RetentionResolver] composes. It is
// redeclared here (rather than importing the clickhouse package) so the
// hibernation package keeps its inward-pointing dependency rule; a
// clickhouse.StaticRetentionResolver / MapRetentionResolver satisfies
// it.
type daysResolver interface {
	RetentionDays(ctx context.Context, tenantID uuid.UUID) int
}

// RetentionResolver is a ClickHouse retention resolver that drives a
// hibernated tenant to the aggressive retention floor, deferring to an
// inner resolver (tier-based, typically) for everyone else. It
// satisfies clickhouse.RetentionResolver structurally, so it drops into
// the writer's Retention slot.
//
// Returning a tiny day count for a parked tenant is safe because the
// writer clamps every result to [MinRetentionDays, MaxRetentionDays]:
// hibernation can only push a tenant DOWN to the 30-day compliance
// floor, never below it, so it never starves the security/audit
// retention guarantee.
type RetentionResolver struct {
	reg            *Registry
	inner          daysResolver
	hibernatedDays int
}

// NewRetentionResolver wraps inner (which may be nil — then a
// non-hibernated tenant resolves to 0, the writer's "defer to default"
// sentinel) with a hibernation override driven by reg. A non-positive
// hibernatedDays uses [DefaultHibernatedRetentionDays].
func NewRetentionResolver(reg *Registry, inner daysResolver, hibernatedDays int) *RetentionResolver {
	if hibernatedDays <= 0 {
		hibernatedDays = DefaultHibernatedRetentionDays
	}
	return &RetentionResolver{reg: reg, inner: inner, hibernatedDays: hibernatedDays}
}

// RetentionDays implements clickhouse.RetentionResolver. A hibernated
// tenant resolves to the aggressive floor; otherwise it defers to the
// inner resolver, or returns 0 (defer to the writer default) when there
// is none.
func (r *RetentionResolver) RetentionDays(ctx context.Context, tenantID uuid.UUID) int {
	if r.reg.IsHibernated(tenantID) {
		return r.hibernatedDays
	}
	if r.inner != nil {
		return r.inner.RetentionDays(ctx, tenantID)
	}
	return 0
}
