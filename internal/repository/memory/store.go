// Package memory is a thread-safe in-memory implementation of the
// repository interfaces. It exists so service-layer code (in
// internal/service/) can be unit-tested without spinning up Postgres.
//
// The implementation is deliberately simple — it favours
// correctness over performance because the only consumers are
// tests. Tenant isolation is enforced by filtering on tenant_id
// in every method, mirroring what Postgres RLS does in
// production.
//
// Cursor pagination is implemented by sorting the matching rows
// and slicing after the cursor offset. The cursor is a small
// JSON blob containing the last-seen sort-key — opaque to callers
// per the interface contract.
package memory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Store is the aggregate in-memory backend. One Store instance is
// the equivalent of one Postgres database — share it between
// repository constructors in tests.
type Store struct {
	mu sync.RWMutex

	// Top-level tenant table (no tenant-scope).
	tenants map[uuid.UUID]repository.Tenant

	// Tenant-scoped tables. Keys are the row id.
	sites             map[uuid.UUID]repository.Site
	users             map[uuid.UUID]repository.User
	devices           map[uuid.UUID]repository.Device
	claimTokens       map[uuid.UUID]repository.ClaimToken
	auditEntries      map[uuid.UUID]repository.AuditEntry
	policyGraphs      map[uuid.UUID]repository.PolicyGraph
	policyBundles     map[uuid.UUID]repository.PolicyBundle
	policySigningKeys map[uuid.UUID]repository.PolicySigningKey
	tenantAPIKeys     map[uuid.UUID]repository.TenantAPIKey
	webhookEndpoints  map[uuid.UUID]repository.WebhookEndpoint
	webhookDeliveries map[uuid.UUID]repository.WebhookDelivery

	// Role / user_role tables. Roles are NOT tenant-scoped on
	// their own (system roles have TenantID nil).
	roles     map[uuid.UUID]repository.Role
	userRoles map[userRoleKey]repository.UserRole

	// clock is injected for deterministic tests. Defaults to
	// time.Now.UTC.
	clock func() time.Time
}

// userRoleKey is the composite key for user_roles. Matches the
// Postgres PRIMARY KEY (user_id, role_id, scope_id_coalesced) so
// the memory store has the same uniqueness semantics.
type userRoleKey struct {
	UserID  uuid.UUID
	RoleID  uuid.UUID
	ScopeID uuid.UUID
}

// NewStore constructs an empty Store backed by `time.Now().UTC()`.
func NewStore() *Store {
	return &Store{
		tenants:           map[uuid.UUID]repository.Tenant{},
		sites:             map[uuid.UUID]repository.Site{},
		users:             map[uuid.UUID]repository.User{},
		devices:           map[uuid.UUID]repository.Device{},
		claimTokens:       map[uuid.UUID]repository.ClaimToken{},
		auditEntries:      map[uuid.UUID]repository.AuditEntry{},
		policyGraphs:      map[uuid.UUID]repository.PolicyGraph{},
		policyBundles:     map[uuid.UUID]repository.PolicyBundle{},
		policySigningKeys: map[uuid.UUID]repository.PolicySigningKey{},
		tenantAPIKeys:     map[uuid.UUID]repository.TenantAPIKey{},
		webhookEndpoints:  map[uuid.UUID]repository.WebhookEndpoint{},
		webhookDeliveries: map[uuid.UUID]repository.WebhookDelivery{},
		roles:             map[uuid.UUID]repository.Role{},
		userRoles:         map[userRoleKey]repository.UserRole{},
		clock:             func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall-clock source. Tests use this to assert
// deterministic CreatedAt / UpdatedAt timestamps.
func (s *Store) SetClock(fn func() time.Time) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = fn
}

// scopeIDOrZero collapses a nil scope_id to the zero-UUID for
// user_role lookup, matching the Postgres COALESCE behaviour.
func scopeIDOrZero(p *uuid.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return *p
}

// cloneJSON returns a deep copy of a json.RawMessage so callers
// cannot mutate stored bytes.
func cloneJSON(in json.RawMessage) json.RawMessage {
	if in == nil {
		return nil
	}
	out := make(json.RawMessage, len(in))
	copy(out, in)
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// encodeCursor renders a sort-key into the opaque base64-encoded
// JSON cursor returned by List operations. The shape is private —
// callers MUST NOT decode it.
type cursor struct {
	// CreatedAt is the canonical sort key for time-ordered lists.
	CreatedAt time.Time `json:"t,omitempty"`
	// ID is appended for tie-breaking when CreatedAt collides
	// (relevant for high-throughput audit-log inserts).
	ID uuid.UUID `json:"i,omitempty"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	if s == "" {
		return cursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	var c cursor
	if err := json.Unmarshal(b, &c); err != nil {
		return cursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	return c, nil
}

// orderBefore reports whether a < b under the given order. ASC means
// "earlier comes first", DESC means "later comes first" — and the
// cursor is the boundary; rows strictly past it are included.
func orderBefore(a, b cursor, order repository.SortOrder) bool {
	if order == repository.SortAsc {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID.String(), b.ID.String()) < 0
		}
		return a.CreatedAt.Before(b.CreatedAt)
	}
	// DESC default.
	if a.CreatedAt.Equal(b.CreatedAt) {
		return strings.Compare(a.ID.String(), b.ID.String()) > 0
	}
	return a.CreatedAt.After(b.CreatedAt)
}

// paginate is a generic helper: given a slice already sorted in the
// desired display order, return up to page.Limit items starting
// strictly past the cursor and the cursor for the next page.
func paginate[T any](items []T, page repository.Page, keyOf func(T) cursor) repository.PageResult[T] {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		// Treat bad cursors as "start over". The interface
		// docs say cursors are opaque, so the only way a
		// caller hits this is by either replaying a stale
		// cursor or crafting one — neither warrants an error
		// in the memory driver. Postgres driver returns an
		// invalid-argument error for safety.
		cur = cursor{}
	}
	out := make([]T, 0, page.Limit)
	skipping := page.After != ""
	for _, it := range items {
		k := keyOf(it)
		if skipping {
			// Skip until we're strictly past the cursor's
			// position in display order. orderBefore(cur, k)
			// is true when k comes after cur in display
			// order. The memory store's display order is
			// the slice order, so we use a forward scan.
			if !orderBefore(cur, k, page.Order) {
				continue
			}
			skipping = false
		}
		out = append(out, it)
		if len(out) >= page.Limit {
			break
		}
	}
	next := ""
	if len(out) == page.Limit && len(items) > 0 {
		// Only emit a non-empty cursor if there might be more
		// data. If we filled the page exactly with the tail,
		// the next call will return an empty page — that's
		// fine.
		next = encodeCursor(keyOf(out[len(out)-1]))
	}
	return repository.PageResult[T]{Items: out, NextCursor: next}
}

// sortByCreatedAtDesc returns a copy of items sorted by CreatedAt
// descending, with id as the tie-breaker. Used by every "time-
// ordered" List operation.
func sortByCreatedAtDesc[T any](items []T, ts func(T) time.Time, id func(T) uuid.UUID, order repository.SortOrder) []T {
	out := make([]T, len(items))
	copy(out, items)
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := ts(out[i]), ts(out[j])
		if !ti.Equal(tj) {
			if order == repository.SortAsc {
				return ti.Before(tj)
			}
			return ti.After(tj)
		}
		// Stable tie-break by id.
		if order == repository.SortAsc {
			return strings.Compare(id(out[i]).String(), id(out[j]).String()) < 0
		}
		return strings.Compare(id(out[i]).String(), id(out[j]).String()) > 0
	})
	return out
}

// errCtxIfNeeded returns the context's error wrapped through the
// repository sentinels so callers can `errors.Is` for either side.
// In practice the memory driver is in-process and never sees a
// cancelled context past the function boundary, but checking up
// front lets tests verify the contract.
func errCtxIfNeeded(ctx context.Context) error {
	return ctx.Err()
}
