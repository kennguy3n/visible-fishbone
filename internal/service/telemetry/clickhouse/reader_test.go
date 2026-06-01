package clickhouse

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// stubRows implements driver.Rows over a slice of pre-canned
// row payloads. We only need Next/Scan/Close/Err to satisfy
// reader.ListFlowEvents.
type stubRows struct {
	rows []scanRow
	idx  int
	err  error
}

// scanRow mirrors the column order in reader.ListFlowEvents'
// SELECT: event_id, tenant_id, device_id, site_id, timestamp,
// event_class, platform, schema_version, traffic_class,
// bytes_in, bytes_out, payload.
type scanRow struct {
	EventID      uuid.UUID
	TenantID     uuid.UUID
	DeviceID     uuid.UUID
	SiteID       *uuid.UUID
	Timestamp    time.Time
	EventClass   string
	Platform     string
	SchemaVer    uint8
	TrafficClass string
	BytesIn      uint64
	BytesOut     uint64
	Payload      string
}

func (s *stubRows) Next() bool {
	if s.err != nil {
		return false
	}
	return s.idx < len(s.rows)
}

func (s *stubRows) Scan(dest ...any) error {
	if s.idx >= len(s.rows) {
		return errors.New("scan past end")
	}
	row := s.rows[s.idx]
	s.idx++
	if len(dest) != 12 {
		return errors.New("expected 12 destination pointers")
	}
	*(dest[0].(*uuid.UUID)) = row.EventID
	*(dest[1].(*uuid.UUID)) = row.TenantID
	*(dest[2].(*uuid.UUID)) = row.DeviceID
	*(dest[3].(**uuid.UUID)) = row.SiteID
	*(dest[4].(*time.Time)) = row.Timestamp
	*(dest[5].(*string)) = row.EventClass
	*(dest[6].(*string)) = row.Platform
	*(dest[7].(*uint8)) = row.SchemaVer
	*(dest[8].(*string)) = row.TrafficClass
	*(dest[9].(*uint64)) = row.BytesIn
	*(dest[10].(*uint64)) = row.BytesOut
	*(dest[11].(*string)) = row.Payload
	return nil
}

func (s *stubRows) ScanStruct(any) error           { return errors.New("not implemented") }
func (s *stubRows) ColumnTypes() []driver.ColumnType { return nil }
func (s *stubRows) Totals(...any) error             { return nil }
func (s *stubRows) Columns() []string {
	return []string{
		"event_id", "tenant_id", "device_id", "site_id",
		"timestamp", "event_class", "platform", "schema_version",
		"traffic_class", "bytes_in", "bytes_out", "payload",
	}
}
func (s *stubRows) Close() error  { return nil }
func (s *stubRows) Err() error    { return s.err }
func (s *stubRows) HasData() bool { return s.idx < len(s.rows) }

// stubQuerier is the smallest Querier that delegates to a
// pre-canned stubRows and remembers the args for assertions.
type stubQuerier struct {
	rows     *stubRows
	queryErr error

	// captured for assertion.
	lastQuery string
	lastArgs  []any
}

func (q *stubQuerier) Query(_ context.Context, query string, args ...any) (driver.Rows, error) {
	q.lastQuery = query
	q.lastArgs = args
	if q.queryErr != nil {
		return nil, q.queryErr
	}
	return q.rows, nil
}

func TestReader_ListFlowEvents_HappyPath(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	devA, devB := uuid.New(), uuid.New()
	siteA := uuid.New()
	ts1 := time.Unix(100, 0).UTC()
	ts2 := time.Unix(101, 0).UTC()

	q := &stubQuerier{rows: &stubRows{rows: []scanRow{
		{
			EventID: uuid.New(), TenantID: tenantID, DeviceID: devA,
			SiteID: &siteA, Timestamp: ts1, EventClass: "flow",
			Platform: "linux", SchemaVer: 1, TrafficClass: "ngfw",
			BytesIn: 100, BytesOut: 200, Payload: "{}",
		},
		{
			EventID: uuid.New(), TenantID: tenantID, DeviceID: devB,
			SiteID: nil, Timestamp: ts2, EventClass: "flow",
			Platform: "darwin", SchemaVer: 1, TrafficClass: "dns",
			BytesIn: 10, BytesOut: 20, Payload: "{}",
		},
	}}}

	r, err := NewReader(q, "")
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	envs, err := r.ListFlowEvents(context.Background(), tenantID,
		ts1.Add(-time.Hour), ts2.Add(time.Hour), 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("envs = %d, want 2", len(envs))
	}
	// Order preserved from stub (writer guarantees ASC).
	if envs[0].DeviceID != devA || envs[1].DeviceID != devB {
		t.Fatalf("ordering mismatch")
	}
	if envs[0].SiteID == nil || *envs[0].SiteID != siteA {
		t.Fatalf("site id not propagated: %v", envs[0].SiteID)
	}
	if envs[1].SiteID != nil {
		t.Fatalf("expected nil site id on env[1], got %v", envs[1].SiteID)
	}
}

func TestReader_ListFlowEvents_RejectsZeroTenant(t *testing.T) {
	t.Parallel()
	r, _ := NewReader(&stubQuerier{rows: &stubRows{}}, "")
	_, err := r.ListFlowEvents(context.Background(), uuid.Nil,
		time.Unix(0, 0), time.Unix(100, 0), 10)
	if err == nil {
		t.Fatalf("expected tenant error")
	}
}

func TestReader_ListFlowEvents_RejectsInvalidWindow(t *testing.T) {
	t.Parallel()
	r, _ := NewReader(&stubQuerier{rows: &stubRows{}}, "")
	// until == since
	_, err := r.ListFlowEvents(context.Background(), uuid.New(),
		time.Unix(100, 0), time.Unix(100, 0), 10)
	if err == nil {
		t.Fatalf("expected window error for since == until")
	}
	// until < since
	_, err = r.ListFlowEvents(context.Background(), uuid.New(),
		time.Unix(200, 0), time.Unix(100, 0), 10)
	if err == nil {
		t.Fatalf("expected window error for since > until")
	}
}

func TestReader_ListFlowEvents_DefaultMaxEvents(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rows: &stubRows{}}
	r, _ := NewReader(q, "")
	_, err := r.ListFlowEvents(context.Background(), uuid.New(),
		time.Unix(0, 0), time.Unix(100, 0), 0) // <=0 → default
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// The last arg of the query is the LIMIT — must be > 0.
	if len(q.lastArgs) != 4 {
		t.Fatalf("expected 4 args, got %d", len(q.lastArgs))
	}
	limit, ok := q.lastArgs[3].(uint64)
	if !ok || limit == 0 {
		t.Fatalf("LIMIT not defaulted: arg=%v (%T)", q.lastArgs[3], q.lastArgs[3])
	}
}

func TestReader_ListFlowEvents_PropagatesQueryError(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{queryErr: errors.New("chql goes boom")}
	r, _ := NewReader(q, "")
	_, err := r.ListFlowEvents(context.Background(), uuid.New(),
		time.Unix(0, 0), time.Unix(100, 0), 10)
	if err == nil {
		t.Fatalf("expected wrap of query error")
	}
}

func TestReader_ListFlowEvents_EmptyResult(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rows: &stubRows{}}
	r, _ := NewReader(q, "")
	envs, err := r.ListFlowEvents(context.Background(), uuid.New(),
		time.Unix(0, 0), time.Unix(100, 0), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(envs) != 0 {
		t.Fatalf("envs = %d, want 0", len(envs))
	}
}

func TestReader_ListFlowEvents_LargeResultSet(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	rows := make([]scanRow, 0, 1000)
	for i := 0; i < 1000; i++ {
		rows = append(rows, scanRow{
			EventID: uuid.New(), TenantID: tenantID,
			DeviceID: uuid.New(), Timestamp: time.Unix(int64(i), 0).UTC(),
			EventClass: "flow", Platform: "linux", SchemaVer: 1,
		})
	}
	q := &stubQuerier{rows: &stubRows{rows: rows}}
	r, _ := NewReader(q, "")
	envs, err := r.ListFlowEvents(context.Background(), tenantID,
		time.Unix(-1, 0), time.Unix(10000, 0), 5000)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(envs) != 1000 {
		t.Fatalf("envs = %d, want 1000", len(envs))
	}
}

func TestNewReader_RejectsNilConn(t *testing.T) {
	t.Parallel()
	if _, err := NewReader(nil, ""); err == nil {
		t.Fatalf("expected error for nil conn")
	}
}

func TestNewReader_RejectsBadTableIdentifier(t *testing.T) {
	t.Parallel()
	if _, err := NewReader(&stubQuerier{rows: &stubRows{}}, "bad name with spaces"); err == nil {
		t.Fatalf("expected error for invalid identifier")
	}
}

func TestNewReader_DefaultsTableName(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rows: &stubRows{}}
	r, err := NewReader(q, "")
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	if r.table != DefaultTable {
		t.Fatalf("table = %q, want %q (DefaultTable)", r.table, DefaultTable)
	}
}

// quoteIdentifier is implementation-internal; tests live in the
// same package so they can verify it's actually called via the
// rendered SELECT.
func TestReader_ListFlowEvents_TableNameInQuery(t *testing.T) {
	t.Parallel()
	q := &stubQuerier{rows: &stubRows{}}
	r, _ := NewReader(q, "")
	_, _ = r.ListFlowEvents(context.Background(), uuid.New(),
		time.Unix(0, 0), time.Unix(100, 0), 10)
	if q.lastQuery == "" {
		t.Fatalf("query not captured")
	}
	wantTable := quoteIdentifier(DefaultTable)
	if !contains(q.lastQuery, wantTable) {
		t.Fatalf("query missing quoted table %q: %s", wantTable, q.lastQuery)
	}
	if !contains(q.lastQuery, "ORDER BY timestamp ASC, event_id ASC") {
		t.Fatalf("query missing deterministic ORDER BY: %s", q.lastQuery)
	}
	if !contains(q.lastQuery, "event_class = 'flow'") {
		t.Fatalf("query missing event_class filter: %s", q.lastQuery)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
