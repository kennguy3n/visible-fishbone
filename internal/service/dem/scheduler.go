// scheduler.go drives the DEM retention sweep. Pruning is a singleton
// workload: in a multi-replica deployment it must run on exactly one
// replica. The Scheduler is leadership-agnostic — Run is meant to be
// wrapped by the leader elector's RunIfLeader so the loop only turns
// while this replica holds leadership (see cmd/sng-control wiring).
package dem

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// DefaultRetentionSweepInterval is how often the retention sweep runs.
// Hourly is ample: retention horizons are measured in days, so an
// hourly sweep keeps table growth bounded without churn.
const DefaultRetentionSweepInterval = time.Hour

// Scheduler periodically prunes expired DEM data.
type Scheduler struct {
	svc      *Service
	logger   *slog.Logger
	interval time.Duration
}

// SchedulerOption customises a Scheduler.
type SchedulerOption func(*Scheduler)

// WithSweepInterval overrides the retention sweep cadence. Non-positive
// values keep the default.
func WithSweepInterval(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.interval = d
		}
	}
}

// WithSchedulerLogger sets the scheduler's structured logger.
func WithSchedulerLogger(l *slog.Logger) SchedulerOption {
	return func(s *Scheduler) {
		if l != nil {
			s.logger = l
		}
	}
}

// NewScheduler constructs a retention Scheduler. svc is required.
func NewScheduler(svc *Service, opts ...SchedulerOption) (*Scheduler, error) {
	if svc == nil {
		return nil, errors.New("dem: NewScheduler requires a service")
	}
	s := &Scheduler{
		svc:      svc,
		logger:   slog.Default(),
		interval: DefaultRetentionSweepInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Run drives the retention sweep until ctx is cancelled. It is
// leadership-agnostic; wrap it with the leader elector's RunIfLeader
// so it only runs on the leader replica:
//
//	go elector.RunIfLeader(ctx, "dem-retention", scheduler.Run)
//
// The first sweep fires one interval after start, not immediately, so
// a freshly elected leader does not stampede a sweep the previous
// leader just finished.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.logger.Info("dem: retention scheduler started", slog.Duration("interval", s.interval))
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("dem: retention scheduler stopped")
			return
		case <-ticker.C:
			if _, _, err := s.svc.PruneRetention(ctx); err != nil {
				s.logger.Error("dem: scheduled retention sweep failed", slog.Any("error", err))
			}
		}
	}
}
