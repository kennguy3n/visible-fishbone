package leader

import (
	"context"
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

// FencingToken identifies a single leadership term. Every singleton
// background task (capacity planning, compliance checks, certificate
// monitor, policy-review scheduler) that runs under leadership should
// stamp its writes with the token returned for that term and reject —
// or have the database reject — any write carrying an older token.
// This is the classic fencing defence against a *stale* leader: a
// replica whose advisory-lock session has died (connection drop,
// network partition the server has detected) but which has not yet
// noticed and stepped down. During that bounded window two replicas
// can briefly believe they are the leader; fencing ensures the stale
// one's writes are rejected because its token is strictly older than
// the new leader's.
//
// LockID is the advisory-lock key the leadership is contended on.
// Epoch is monotonically increasing across the WHOLE database
// cluster (and therefore across process restarts) when leadership is
// backed by a Postgres session that implements EpochReader — the
// production path derives it from the transaction id at the instant
// the lock is acquired. A higher Epoch always denotes a newer term.
type FencingToken struct {
	LockID int64
	Epoch  uint64
}

// Valid reports whether the token names a real leadership term. The
// zero token (Epoch == 0) is what callers receive when they were not
// the leader, so it never authorises a write.
func (t FencingToken) Valid() bool { return t.Epoch != 0 }

// NewerThan reports whether t belongs to a strictly newer leadership
// term than other. A persistence layer enforcing fencing keeps the
// highest Epoch it has seen for a given LockID and rejects any write
// whose token is not NewerThan-or-equal to it.
func (t FencingToken) NewerThan(other FencingToken) bool {
	return t.LockID == other.LockID && t.Epoch > other.Epoch
}

// EpochReader is an OPTIONAL capability a Session may implement to
// supply a globally monotonic fencing epoch. The production pgSession
// implements it via the Postgres transaction id, which is monotonic
// across the cluster and survives restarts. A Session that does not
// implement it (e.g. the in-memory test fake) causes the elector to
// fall back to its in-process generation counter, which is adequate
// for a single process but not across restarts.
type EpochReader interface {
	// Epoch returns a value that strictly increases each time it is
	// observed across the database, used as the fencing epoch for
	// the leadership term being acquired.
	Epoch(ctx context.Context) (uint64, error)
}

// acquireEpoch derives the fencing epoch for a freshly acquired
// leadership term. It prefers the session's globally monotonic
// EpochReader and falls back to the in-process generation counter
// when the session does not provide one (or the read fails).
func (e *LeaderElector) acquireEpoch(ctx context.Context, sess Session) uint64 {
	if er, ok := sess.(EpochReader); ok {
		if v, err := er.Epoch(ctx); err == nil && v != 0 {
			return v
		} else if err != nil {
			e.logger.Warn("leader: fencing epoch read failed; falling back to generation counter",
				slog.Any("error", err))
		}
	}
	return e.generation.Load()
}

// FencingToken returns the fencing token for the current leadership
// term and whether this replica currently holds leadership. When the
// caller is not the leader it returns the zero token and false, so a
// follower can never produce a token that authorises a write.
func (e *LeaderElector) FencingToken() (FencingToken, bool) {
	if !e.IsLeader() {
		return FencingToken{}, false
	}
	return FencingToken{LockID: e.lockID, Epoch: e.epoch.Load()}, true
}

// HoldsToken reports whether tok still names THIS replica's live
// leadership term. A background task should call this immediately
// before committing a leader-scoped write so that a step-down or a
// leadership flap between the start of the work and the commit is
// caught even when the database is not the fencing enforcement point.
// It returns false once leadership is lost or the term has advanced.
func (e *LeaderElector) HoldsToken(tok FencingToken) bool {
	return e.IsLeader() && tok.LockID == e.lockID && tok.Epoch == e.epoch.Load()
}

// RunIfLeaderFenced behaves like RunIfLeader but hands fn the fencing
// token for the leadership term the job is running under. fn should
// stamp its writes with the token and re-check HoldsToken before
// committing. The token is captured once when the job starts; if
// leadership flaps the job's context is cancelled and fn is restarted
// with a fresh token (matching RunIfLeader's restart semantics).
func (e *LeaderElector) RunIfLeaderFenced(ctx context.Context, name string, fn func(context.Context, FencingToken)) {
	e.RunIfLeader(ctx, name, func(runCtx context.Context) {
		tok, ok := e.FencingToken()
		if !ok {
			// Leadership was lost between RunIfLeader's check and
			// here; return so the loop re-evaluates rather than
			// running fn with an invalid token.
			return
		}
		fn(runCtx, tok)
	})
}

// WithTransitionsCounter wires the sng_leader_transitions_total
// counter. The elector increments it on every leadership acquisition
// (each 0->leader edge), so rate(sng_leader_transitions_total[5m])
// surfaces election churn / flapping. Passing a nil counter is a
// no-op. Prefer WithTransitionsMetric, which constructs and registers
// the canonical metric for you.
func WithTransitionsCounter(c prometheus.Counter) Option {
	return func(e *LeaderElector) { e.transitions = c }
}

// WithTransitionsMetric constructs and registers the
// sng_leader_transitions_total counter against reg and wires it into
// the elector. namespace defaults to "sng" when empty so the exported
// series reads sng_leader_transitions_total. A nil registerer is a
// no-op. If an equivalent counter is already registered (e.g. two
// electors share a registry) the existing collector is reused rather
// than panicking.
func WithTransitionsMetric(reg prometheus.Registerer, namespace string) Option {
	return func(e *LeaderElector) {
		if reg == nil {
			return
		}
		if namespace == "" {
			namespace = "sng"
		}
		c := prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "leader",
			Name:      "transitions_total",
			Help:      "Total number of leadership acquisitions (0->leader transitions) observed by this replica.",
		})
		if err := reg.Register(c); err != nil {
			var are prometheus.AlreadyRegisteredError
			if errors.As(err, &are) {
				if existing, ok := are.ExistingCollector.(prometheus.Counter); ok {
					e.transitions = existing
				}
				return
			}
			// A non-duplicate registration error is a programming
			// error in metric naming; surface it via the logger
			// rather than panicking the elector construction.
			e.logger.Warn("leader: could not register transitions metric", slog.Any("error", err))
			return
		}
		e.transitions = c
	}
}
