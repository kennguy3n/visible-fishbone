package leader

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PgSessionOpener acquires dedicated sessions from a pgx pool for
// advisory-lock leadership. It hands out a single pooled connection
// per Session and holds it for the lock's lifetime, so it consumes
// at most one pool slot per held lock (one, in the common case of a
// single elector). Use the PRIMARY pool — advisory locks are taken
// on the primary, never a read replica.
type PgSessionOpener struct {
	pool *pgxpool.Pool
}

// NewPgSessionOpener returns a SessionOpener backed by pool.
func NewPgSessionOpener(pool *pgxpool.Pool) *PgSessionOpener {
	return &PgSessionOpener{pool: pool}
}

// Open acquires one connection from the pool and wraps it as a
// Session. The connection is held until Session.Close.
func (o *PgSessionOpener) Open(ctx context.Context) (Session, error) {
	if o.pool == nil {
		return nil, fmt.Errorf("leader: nil pool")
	}
	conn, err := o.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("leader: acquire connection: %w", err)
	}
	return &pgSession{conn: conn}, nil
}

// pgSession holds one acquired pooled connection. It is used only by
// the single election goroutine, so it needs no internal locking.
type pgSession struct {
	conn *pgxpool.Conn
}

func (s *pgSession) TryLock(ctx context.Context, lockID int64) (bool, error) {
	var locked bool
	// pg_try_advisory_lock takes a session-level lock that is held
	// until pg_advisory_unlock or the session ends — exactly the
	// failover semantics the elector relies on.
	if err := s.conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&locked); err != nil {
		return false, fmt.Errorf("leader: pg_try_advisory_lock: %w", err)
	}
	return locked, nil
}

func (s *pgSession) Unlock(ctx context.Context, lockID int64) error {
	var unlocked bool
	if err := s.conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&unlocked); err != nil {
		return fmt.Errorf("leader: pg_advisory_unlock: %w", err)
	}
	if !unlocked {
		// The session did not actually hold the lock; surface it so
		// a logic error (double-unlock) is visible rather than
		// silently swallowed.
		return fmt.Errorf("leader: advisory lock %d was not held by this session", lockID)
	}
	return nil
}

func (s *pgSession) Ping(ctx context.Context) error {
	return s.conn.Ping(ctx)
}

func (s *pgSession) Close(_ context.Context) {
	// Release returns the connection to the pool. pgxpool discards a
	// connection whose session state is broken, so a dead connection
	// is not reused.
	s.conn.Release()
}
