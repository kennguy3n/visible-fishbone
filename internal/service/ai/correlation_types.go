package ai

import (
	"time"

	"github.com/google/uuid"
)

// CorrelationDimension identifies a correlation axis.
type CorrelationDimension string

const (
	CorrelationDimensionTemporal CorrelationDimension = "temporal"
	CorrelationDimensionEntity   CorrelationDimension = "entity"
	CorrelationDimensionPattern  CorrelationDimension = "pattern"
)

// CorrelationConfig tunes the correlation engine.
type CorrelationConfig struct {
	// TimeWindow is the maximum time span between two related
	// alerts. Defaults to 1 hour.
	TimeWindow time.Duration
	// MinClusterSize is the smallest alert group that constitutes
	// a cluster. Defaults to 2.
	MinClusterSize int
}

func (c CorrelationConfig) normalize() CorrelationConfig {
	if c.TimeWindow <= 0 {
		c.TimeWindow = time.Hour
	}
	if c.MinClusterSize <= 0 {
		c.MinClusterSize = 2
	}
	return c
}

// AlertInput is a simplified alert representation consumed by the
// correlation engine. Callers map their domain-specific alert types
// into this shape.
type AlertInput struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	DeviceID  string    `json:"device_id"`
	UserID    string    `json:"user_id"`
	IPAddress string    `json:"source_ip"`
	CreatedAt time.Time `json:"timestamp"`
}

// CorrelationCluster is the output of the correlation engine: a
// group of related alerts and a summary.
//
// ID is a pointer because it is meaningful only once the cluster has
// been persisted: it carries the repository-assigned ID (retrievable
// via GET /ai/correlations/{id}) and is nil for an ephemeral cluster
// that was not stored (no repository wired, or a persistence failure).
// A nil ID serialises as JSON null rather than a zero UUID that would
// 404, so the contract is "id is non-null iff the cluster is
// retrievable". The engine itself never assigns an ID.
type CorrelationCluster struct {
	ID         *uuid.UUID             `json:"id,omitempty"`
	TenantID   uuid.UUID              `json:"tenant_id"`
	AlertIDs   []uuid.UUID            `json:"alert_ids"`
	Summary    string                 `json:"summary"`
	Severity   string                 `json:"severity"`
	Status     string                 `json:"status"`
	Dimensions []CorrelationDimension `json:"dimensions"`
	CreatedAt  time.Time              `json:"created_at"`
}

// CorrelationResult wraps the output of a full correlation run.
type CorrelationResult struct {
	Clusters         []CorrelationCluster `json:"clusters"`
	TotalAlerts      int                  `json:"total_alerts"`
	CorrelatedAlerts int                  `json:"correlated_alerts"`
	AIGenerated      bool                 `json:"ai_generated"`
}
