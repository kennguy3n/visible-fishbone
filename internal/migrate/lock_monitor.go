package migrate

// lock_monitor.go guards DDL execution against lock contention. At
// 5,000 tenants a migration that grabs ACCESS EXCLUSIVE on a hot
// table behind a long-running transaction queues every other query
// behind it — a single migration becomes a global stall. The
// LockMonitor (a) sets a bounded `lock_timeout` so a blocked DDL
// fails fast instead of holding the queue, and (b) samples
// `pg_locks` before running DDL and backs off exponentially while a
// table is busy.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the minimal pgx surface the LockMonitor needs. Both
// *pgx.Conn, *pgxpool.Pool, and pgx.Tx satisfy it without adapters,
// mirroring the pattern in internal/testutil/pgrole. Keeping it tiny
// also makes the monitor trivial to fake in unit tests.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Default tuning for the LockMonitor. Exported so callers and tests
// can reference the same constants the CLI documents.
const (
	// DefaultMaxActiveTxns is the contention threshold: when more
	// than this many distinct backends hold or wait on a lock against
	// the target table, the monitor backs off rather than piling on.
	DefaultMaxActiveTxns = 100
	// DefaultLockTimeout bounds how long any single DDL statement
	// waits for its lock before erroring out. Five seconds is long
	// enough to win an uncontended lock and short enough that a
	// blocked migration never parks ACCESS EXCLUSIVE behind a slow
	// transaction.
	DefaultLockTimeout = 5 * time.Second
	// DefaultBaseBackoff / DefaultMaxBackoff bound the exponential
	// wait between contention samples.
	DefaultBaseBackoff = 100 * time.Millisecond
	DefaultMaxBackoff  = 10 * time.Second
	// DefaultMaxBackoffAttempts caps how many times the monitor
	// re-samples before giving up with ErrContentionTimeout.
	DefaultMaxBackoffAttempts = 8
)

// ErrContention is returned by WaitForLowContention when the target
// table is still above the active-transaction threshold after the
// configured number of backoff attempts.
var ErrContention = errors.New("migrate: table lock contention did not clear within backoff budget")

// LockMonitorConfig tunes a LockMonitor. The zero value is not
// usable directly; construct via NewLockMonitor which fills defaults.
type LockMonitorConfig struct {
	MaxActiveTxns      int
	LockTimeout        time.Duration
	BaseBackoff        time.Duration
	MaxBackoff         time.Duration
	MaxBackoffAttempts int
	// sleep is injectable so unit tests do not wait in real time. nil
	// means time.Sleep honouring context cancellation.
	sleep func(context.Context, time.Duration) error
}

// LockMonitor samples lock contention and applies lock_timeout.
type LockMonitor struct {
	cfg LockMonitorConfig
}

// NewLockMonitor returns a LockMonitor, replacing any zero/negative
// config field with its default.
func NewLockMonitor(cfg LockMonitorConfig) *LockMonitor {
	if cfg.MaxActiveTxns <= 0 {
		cfg.MaxActiveTxns = DefaultMaxActiveTxns
	}
	if cfg.LockTimeout <= 0 {
		cfg.LockTimeout = DefaultLockTimeout
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.MaxBackoffAttempts <= 0 {
		cfg.MaxBackoffAttempts = DefaultMaxBackoffAttempts
	}
	if cfg.sleep == nil {
		cfg.sleep = sleepCtx
	}
	return &LockMonitor{cfg: cfg}
}

// LockTimeout reports the configured per-statement lock timeout.
func (lm *LockMonitor) LockTimeout() time.Duration { return lm.cfg.LockTimeout }

// MaxActiveTxns reports the configured contention threshold.
func (lm *LockMonitor) MaxActiveTxns() int { return lm.cfg.MaxActiveTxns }

// ApplyLockTimeout sets `lock_timeout` on the session backing q. Use
// it once per connection before issuing DDL. The value is rendered
// as integer milliseconds, which is the unit Postgres assumes for a
// unit-less lock_timeout, so no quoting of operator input is
// involved (the value is derived from a time.Duration, not a string).
func (lm *LockMonitor) ApplyLockTimeout(ctx context.Context, q Querier) error {
	ms := lm.cfg.LockTimeout.Milliseconds()
	if ms <= 0 {
		ms = DefaultLockTimeout.Milliseconds()
	}
	// SET does not accept bind parameters for the value, so the
	// integer is formatted directly. It originates from a
	// time.Duration and can never be attacker-controlled SQL.
	stmt := fmt.Sprintf("SET lock_timeout = %d", ms)
	if _, err := q.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("set lock_timeout: %w", err)
	}
	return nil
}

// CountActiveLockers returns the number of distinct backends (other
// than this one) that currently hold or wait on a lock against
// table. It is an estimate of how contended the table is right now;
// pg_locks is a live snapshot, so the value can change between the
// sample and the subsequent DDL — the bounded lock_timeout is the
// real safety net, the count is the politeness check.
func (lm *LockMonitor) CountActiveLockers(ctx context.Context, q Querier, table string) (int, error) {
	const q1 = `
SELECT count(DISTINCT l.pid)
FROM pg_locks l
JOIN pg_class c ON c.oid = l.relation
WHERE c.relname = $1
  AND l.pid IS NOT NULL
  AND l.pid <> pg_backend_pid()`
	var n int
	if err := q.QueryRow(ctx, q1, table).Scan(&n); err != nil {
		return 0, fmt.Errorf("count active lockers on %q: %w", table, err)
	}
	return n, nil
}

// WaitForLowContention samples CountActiveLockers and, while the
// count exceeds MaxActiveTxns, waits with exponential backoff
// (BaseBackoff, doubling, capped at MaxBackoff) up to
// MaxBackoffAttempts times. It returns nil as soon as contention is
// at or below the threshold, ErrContention if the budget is
// exhausted, or the context error if ctx is cancelled while waiting.
func (lm *LockMonitor) WaitForLowContention(ctx context.Context, q Querier, table string) error {
	backoff := lm.cfg.BaseBackoff
	for attempt := 0; ; attempt++ {
		n, err := lm.CountActiveLockers(ctx, q, table)
		if err != nil {
			return err
		}
		if n <= lm.cfg.MaxActiveTxns {
			return nil
		}
		if attempt >= lm.cfg.MaxBackoffAttempts {
			return fmt.Errorf("%w: %q has %d active lockers (threshold %d) after %d attempts",
				ErrContention, table, n, lm.cfg.MaxActiveTxns, lm.cfg.MaxBackoffAttempts)
		}
		if err := lm.cfg.sleep(ctx, backoff); err != nil {
			return err
		}
		backoff *= 2
		if backoff > lm.cfg.MaxBackoff {
			backoff = lm.cfg.MaxBackoff
		}
	}
}

// sleepCtx sleeps for d but returns early with ctx.Err() if the
// context is cancelled first, so a cancelled migration unwinds
// promptly instead of parking in a backoff sleep.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
