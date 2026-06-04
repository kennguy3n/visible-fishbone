package migrate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeRow implements pgx.Row over a single int value (or an error),
// which is all CountActiveLockers scans.
type fakeRow struct {
	n   int
	err error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("fakeRow: expected exactly one scan dest")
	}
	p, ok := dest[0].(*int)
	if !ok {
		return errors.New("fakeRow: scan dest is not *int")
	}
	*p = r.n
	return nil
}

// fakeQuerier returns a scripted sequence of locker counts and
// records every Exec it sees, so tests can assert on lock_timeout
// statements without a database.
type fakeQuerier struct {
	counts   []int
	queryErr error
	idx      int
	execs    []string
}

func (q *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	if q.queryErr != nil {
		return fakeRow{err: q.queryErr}
	}
	var n int
	if q.idx < len(q.counts) {
		n = q.counts[q.idx]
	} else if len(q.counts) > 0 {
		n = q.counts[len(q.counts)-1]
	}
	q.idx++
	return fakeRow{n: n}
}

func (q *fakeQuerier) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	q.execs = append(q.execs, sql)
	return pgconn.CommandTag{}, nil
}

func newTestMonitor(maxActive int) (*LockMonitor, *int) {
	sleeps := 0
	lm := NewLockMonitor(LockMonitorConfig{
		MaxActiveTxns:      maxActive,
		BaseBackoff:        time.Millisecond,
		MaxBackoff:         2 * time.Millisecond,
		MaxBackoffAttempts: 4,
		sleep: func(context.Context, time.Duration) error {
			sleeps++
			return nil
		},
	})
	return lm, &sleeps
}

func TestLockMonitor_Defaults(t *testing.T) {
	lm := NewLockMonitor(LockMonitorConfig{})
	if lm.MaxActiveTxns() != DefaultMaxActiveTxns {
		t.Errorf("want default max active %d, got %d", DefaultMaxActiveTxns, lm.MaxActiveTxns())
	}
	if lm.LockTimeout() != DefaultLockTimeout {
		t.Errorf("want default lock timeout %v, got %v", DefaultLockTimeout, lm.LockTimeout())
	}
}

func TestLockMonitor_ApplyLockTimeout(t *testing.T) {
	lm := NewLockMonitor(LockMonitorConfig{LockTimeout: 5 * time.Second})
	q := &fakeQuerier{}
	if err := lm.ApplyLockTimeout(context.Background(), q); err != nil {
		t.Fatalf("ApplyLockTimeout: %v", err)
	}
	if len(q.execs) != 1 || q.execs[0] != "SET lock_timeout = 5000" {
		t.Fatalf("unexpected execs: %v", q.execs)
	}
}

func TestLockMonitor_WaitClearsImmediately(t *testing.T) {
	lm, sleeps := newTestMonitor(100)
	q := &fakeQuerier{counts: []int{10}}
	if err := lm.WaitForLowContention(context.Background(), q, "devices"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if *sleeps != 0 {
		t.Errorf("expected no sleeps when contention is already low, got %d", *sleeps)
	}
}

func TestLockMonitor_WaitBacksOffThenClears(t *testing.T) {
	lm, sleeps := newTestMonitor(100)
	// Two samples over threshold, then it clears.
	q := &fakeQuerier{counts: []int{500, 300, 50}}
	if err := lm.WaitForLowContention(context.Background(), q, "devices"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if *sleeps != 2 {
		t.Errorf("expected 2 backoff sleeps, got %d", *sleeps)
	}
}

func TestLockMonitor_WaitExhaustsBudget(t *testing.T) {
	lm, _ := newTestMonitor(100)
	q := &fakeQuerier{counts: []int{999}} // always over threshold
	err := lm.WaitForLowContention(context.Background(), q, "devices")
	if !errors.Is(err, ErrContention) {
		t.Fatalf("want ErrContention, got %v", err)
	}
}

func TestLockMonitor_WaitPropagatesQueryError(t *testing.T) {
	lm, _ := newTestMonitor(100)
	q := &fakeQuerier{queryErr: errors.New("boom")}
	if err := lm.WaitForLowContention(context.Background(), q, "devices"); err == nil {
		t.Fatal("expected query error to propagate")
	}
}

func TestLockMonitor_WaitHonorsContextCancel(t *testing.T) {
	cancelled := errors.New("cancelled")
	lm := NewLockMonitor(LockMonitorConfig{
		MaxActiveTxns:      1,
		MaxBackoffAttempts: 4,
		sleep: func(context.Context, time.Duration) error {
			return cancelled
		},
	})
	q := &fakeQuerier{counts: []int{999}}
	if err := lm.WaitForLowContention(context.Background(), q, "devices"); !errors.Is(err, cancelled) {
		t.Fatalf("want cancelled sleep error, got %v", err)
	}
}
