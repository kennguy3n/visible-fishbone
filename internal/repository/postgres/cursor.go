package postgres

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// pageCursor is the opaque cursor format shared by every paginated
// List query. The shape is intentionally private — callers must
// treat the encoded string as opaque per the
// repository.PageResult.NextCursor contract.
type pageCursor struct {
	// T is the sort-key timestamp (CreatedAt for time-ordered
	// listings).
	T time.Time `json:"t,omitempty"`
	// I is the tie-breaker UUID for rows that share the same
	// timestamp (audit-log floods, identical migration timestamps,
	// etc.). Postgres ORDER BY (created_at, id) yields a stable
	// total order that matches this cursor format.
	I uuid.UUID `json:"i,omitempty"`
}

func encodeCursor(c pageCursor) string {
	if c.T.IsZero() && c.I == uuid.Nil {
		return ""
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (pageCursor, error) {
	if s == "" {
		return pageCursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pageCursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	var c pageCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return pageCursor{}, fmt.Errorf("decode cursor: %w", err)
	}
	return c, nil
}
