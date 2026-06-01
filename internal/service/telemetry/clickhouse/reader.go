// Package clickhouse — reader.go implements the read side of the
// hot tier. It surfaces flow envelopes for the policy simulator
// (internal/service/policy.Simulator) and any other consumer
// that wants a deterministic replay of recent telemetry without
// reaching into the cold tier (S3).
//
// The Reader is deliberately a thin SELECT wrapper. Why a
// separate type from Writer:
//
//   - Writer holds the background-flush goroutine + the prepared
//     INSERT batch. Reader has no batching, no goroutine, and no
//     ALTER-TABLE retry path. Fusing them would force a single
//     lifecycle on two very different workloads (ingestion is a
//     long-lived service; read is on the operator-request hot
//     path).
//   - Reader's interface is implementation-defined for testability:
//     a small Querier interface so tests can supply an in-memory
//     stub without a ClickHouse testcontainer. The Writer's
//     surface is wired to a concrete driver.Conn because its
//     prepared-batch optimisation needs the concrete type.
//
// Determinism: SELECT ORDER BY (timestamp, event_id) is the
// stable order the simulator relies on; the (tenant_id,
// event_class, traffic_class, timestamp, event_id) PRIMARY KEY
// in the migration ensures this ORDER BY is satisfied from the
// index without a sort.

package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// Querier is the minimal driver.Conn subset the Reader uses. A
// real *clickhouse.Conn satisfies it; tests inject a stub.
type Querier interface {
	Query(ctx context.Context, query string, args ...any) (driver.Rows, error)
}

// Reader is a read-only ClickHouse client scoped to a single
// sng_telemetry-shaped table. Construct via NewReader.
type Reader struct {
	conn  Querier
	table string
}

// NewReader builds a Reader. The table name MUST match the
// Writer's Config.Table (default: DefaultTable). A non-default
// table needs the same name spelled identically here, in the
// Writer config, and in the migration — see the existing
// TestMigrationFileMatchesEnsureSchemaIntent for the parity
// contract.
func NewReader(conn Querier, table string) (*Reader, error) {
	if conn == nil {
		return nil, errors.New("clickhouse reader: conn is required")
	}
	if table == "" {
		table = DefaultTable
	}
	if err := validateIdentifier("reader.Table", table); err != nil {
		return nil, err
	}
	return &Reader{conn: conn, table: table}, nil
}

// NewReader is a convenience on Writer that returns a Reader
// sharing the Writer's existing ClickHouse connection. The
// Reader's lifecycle is bound to the Writer — when the Writer
// stops, the Reader can no longer issue queries. Use this in
// production so a binary with one Writer connection doesn't
// open a second one just for reads.
func (w *Writer) NewReader() (*Reader, error) {
	if w == nil || w.conn == nil {
		return nil, errors.New("clickhouse reader: writer not ready")
	}
	return NewReader(w.conn, w.cfg.Table)
}

// NewReaderFromConfig is a convenience that opens a fresh
// ClickHouse connection from the same Config used to construct
// a Writer. The returned Reader holds its OWN connection so
// closing the Writer doesn't tear the Reader down — the two
// have independent lifecycles per the package header. Callers
// must Close the Reader when done; nothing else does.
func NewReaderFromConfig(ctx context.Context, cfg Config) (*Reader, *clickhouseHandle, error) {
	cfg.fillDefaults()
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	opts := &clickhouse.Options{
		Addr: cfg.Endpoints,
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		DialTimeout: cfg.DialTimeout,
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
	}
	if cfg.TLS {
		opts.TLS = newTLSConfig()
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("clickhouse reader: open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("clickhouse reader: ping: %w", err)
	}
	r, rErr := NewReader(conn, cfg.Table)
	if rErr != nil {
		_ = conn.Close()
		return nil, nil, rErr
	}
	return r, &clickhouseHandle{conn: conn}, nil
}

// clickhouseHandle is a tiny owner-of-the-connection wrapper so
// the caller can Close() the Reader's underlying connection
// without the Reader itself having to know about lifetime
// semantics for the injected-Querier case.
type clickhouseHandle struct{ conn driver.Conn }

// Close shuts down the underlying connection.
func (h *clickhouseHandle) Close() error {
	if h == nil || h.conn == nil {
		return nil
	}
	return h.conn.Close()
}

// ListFlowEvents returns envelopes for (tenant_id, event_class
// = "flow") in the given [since, until] window, ordered by
// (timestamp, event_id) ascending. maxEvents bounds the result
// — the simulator caps at DefaultSimulationMaxEvents.
//
// since is closed; until is open (LT, not LE) so caller-supplied
// "now" windows are consistent with the writer's
// "timestamp < now" convention used in the retention path.
func (r *Reader) ListFlowEvents(
	ctx context.Context,
	tenantID uuid.UUID,
	since, until time.Time,
	maxEvents int,
) ([]schema.Envelope, error) {
	if tenantID == uuid.Nil {
		return nil, errors.New("clickhouse reader: tenant_id required")
	}
	if !until.After(since) {
		return nil, errors.New("clickhouse reader: until must be after since")
	}
	if maxEvents <= 0 {
		maxEvents = 1000
	}

	// Pre-validated table identifier (we own it via the
	// constructor) is safe to interpolate; everything else is
	// parameterised so the operator cannot inject SQL via the
	// tenant_id or window.
	q := fmt.Sprintf(`SELECT
event_id, tenant_id, device_id, site_id,
timestamp, event_class, platform, schema_version,
traffic_class, bytes_in, bytes_out, payload
FROM %s
WHERE tenant_id = ? AND event_class = 'flow'
  AND timestamp >= ? AND timestamp < ?
ORDER BY timestamp ASC, event_id ASC
LIMIT ?`, quoteIdentifier(r.table))
	rows, err := r.conn.Query(ctx, q, tenantID, since, until, uint64(maxEvents))
	if err != nil {
		return nil, fmt.Errorf("clickhouse reader: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]schema.Envelope, 0, maxEvents)
	for rows.Next() {
		var (
			envelopeID  uuid.UUID
			tid         uuid.UUID
			deviceID    uuid.UUID
			siteRaw     *uuid.UUID
			ts          time.Time
			eventClass  string
			platform    string
			schemaVer   uint8
			trafficCls  string
			bytesIn     uint64
			bytesOut    uint64
			payload     string
		)
		if err := rows.Scan(
			&envelopeID, &tid, &deviceID, &siteRaw,
			&ts, &eventClass, &platform, &schemaVer,
			&trafficCls, &bytesIn, &bytesOut, &payload,
		); err != nil {
			return nil, fmt.Errorf("clickhouse reader: scan: %w", err)
		}
		out = append(out, schema.Envelope{
			EventID:       envelopeID,
			TenantID:      tid,
			DeviceID:      deviceID,
			SiteID:        siteRaw,
			Timestamp:     ts,
			EventClass:    schema.EventClass(eventClass),
			Platform:      schema.Platform(platform),
			SchemaVersion: schemaVer,
			TrafficClass:  trafficCls,
			BytesIn:       bytesIn,
			BytesOut:      bytesOut,
			Payload:       []byte(payload),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("clickhouse reader: rows: %w", err)
	}
	return out, nil
}
