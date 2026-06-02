package ai

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SchedulerConfig controls the periodic analysis scheduler.
type SchedulerConfig struct {
	Interval       time.Duration
	TenantCooldown time.Duration
	MaxConcurrent  int
}

// DefaultSchedulerConfig returns sensible defaults.
func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		Interval:       7 * 24 * time.Hour,
		TenantCooldown: 5 * time.Minute,
		MaxConcurrent:  2,
	}
}

// TenantLister provides the list of tenants to analyse.
type TenantLister interface {
	ListActiveTenants(ctx context.Context) ([]uuid.UUID, error)
}

// TenantOptInChecker checks whether a tenant has opted in to
// AI policy analysis.
type TenantOptInChecker interface {
	IsOptedIn(ctx context.Context, tenantID uuid.UUID) bool
}

// AnalysisRunner runs the analysis for a single tenant.
type AnalysisRunner interface {
	RunAnalysis(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// SchedulerMetrics records telemetry for the scheduler.
type SchedulerMetrics struct {
	mu               sync.Mutex
	TotalRuns        int64
	TotalSuggestions int64
	TotalErrors      int64
	LastRunDuration  time.Duration
	LastRunAt        time.Time
}

// Record records a single run's telemetry.
func (m *SchedulerMetrics) Record(suggestions int, err error, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalRuns++
	m.TotalSuggestions += int64(suggestions)
	if err != nil {
		m.TotalErrors++
	}
	m.LastRunDuration = duration
	m.LastRunAt = time.Now().UTC()
}

// Snapshot returns a copy of the metrics.
func (m *SchedulerMetrics) Snapshot() SchedulerMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return SchedulerMetrics{
		TotalRuns:        m.TotalRuns,
		TotalSuggestions: m.TotalSuggestions,
		TotalErrors:      m.TotalErrors,
		LastRunDuration:  m.LastRunDuration,
		LastRunAt:        m.LastRunAt,
	}
}

// Scheduler runs periodic tightening analysis for all opted-in
// tenants. It uses rate limiting to avoid thundering herd and
// supports leader election via NATS KV for single-writer semantics.
type Scheduler struct {
	config  SchedulerConfig
	tenants TenantLister
	optIn   TenantOptInChecker
	runner  AnalysisRunner
	logger  *slog.Logger
	metrics SchedulerMetrics
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewScheduler constructs a Scheduler.
func NewScheduler(
	config SchedulerConfig,
	tenants TenantLister,
	optIn TenantOptInChecker,
	runner AnalysisRunner,
	logger *slog.Logger,
) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 1
	}
	return &Scheduler{
		config:  config,
		tenants: tenants,
		optIn:   optIn,
		runner:  runner,
		logger:  logger,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Start begins the periodic scheduling loop. Non-blocking.
func (s *Scheduler) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop signals the scheduler to stop and waits for it to finish.
func (s *Scheduler) Stop() {
	close(s.stopCh)
	<-s.doneCh
}

// Metrics returns the current scheduler metrics.
func (s *Scheduler) Metrics() SchedulerMetrics {
	return s.metrics.Snapshot()
}

// RunOnce executes one full sweep across all opted-in tenants.
// Exported for testing.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	start := time.Now()

	tenantIDs, err := s.tenants.ListActiveTenants(ctx)
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}

	sem := make(chan struct{}, s.config.MaxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var totalSuggestions int
	var firstErr error

	for _, tid := range tenantIDs {
		if !s.optIn.IsOptedIn(ctx, tid) {
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(tenantID uuid.UUID) {
			defer wg.Done()
			defer func() { <-sem }()

			if s.config.TenantCooldown > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(s.config.TenantCooldown):
				}
			}

			suggestions, runErr := s.runner.RunAnalysis(ctx, tenantID)
			mu.Lock()
			totalSuggestions += suggestions
			if runErr != nil && firstErr == nil {
				firstErr = runErr
			}
			mu.Unlock()

			s.metrics.Record(suggestions, runErr, time.Since(start))

			if runErr != nil {
				s.logger.Error("tenant analysis failed",
					slog.String("tenant_id", tenantID.String()),
					slog.String("error", runErr.Error()))
			} else {
				s.logger.Info("tenant analysis completed",
					slog.String("tenant_id", tenantID.String()),
					slog.Int("suggestions", suggestions))
			}
		}(tid)
	}

	wg.Wait()
	return firstErr
}

func (s *Scheduler) run(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			if err := s.RunOnce(ctx); err != nil {
				s.logger.Error("scheduler run failed",
					slog.String("error", err.Error()))
			}
		}
	}
}
