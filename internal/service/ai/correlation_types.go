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
	ID        uuid.UUID
	TenantID  uuid.UUID
	Kind      string
	Severity  string
	DeviceID  string
	UserID    string
	IPAddress string
	CreatedAt time.Time
}

// CorrelationCluster is the output of the correlation engine: a
// group of related alerts and a summary.
type CorrelationCluster struct {
	ID         uuid.UUID            `json:"id"`
	TenantID   uuid.UUID            `json:"tenant_id"`
	AlertIDs   []uuid.UUID          `json:"alert_ids"`
	Summary    string               `json:"summary"`
	Severity   string               `json:"severity"`
	Status     string               `json:"status"`
	Dimensions []CorrelationDimension `json:"dimensions"`
	CreatedAt  time.Time            `json:"created_at"`
}

// CorrelationResult wraps the output of a full correlation run.
type CorrelationResult struct {
	Clusters         []CorrelationCluster `json:"clusters"`
	TotalAlerts      int                  `json:"total_alerts"`
	CorrelatedAlerts int                  `json:"correlated_alerts"`
	AIGenerated      bool                 `json:"ai_generated"`
}
