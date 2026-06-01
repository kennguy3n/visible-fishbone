package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// -----------------------------------------------------------------
// IntegrationConnectorRepository
// -----------------------------------------------------------------

// IntegrationConnectorRepository owns integration_connectors. Shape
// mirrors WebhookEndpointRepository — same RLS scoping, same
// pagination contract — so the dispatcher's operational tooling can
// treat the two pipes interchangeably.
type IntegrationConnectorRepository struct{ s *Store }

const integrationConnectorSelectColumns = `
	id, tenant_id, type, name, description, event_types,
	config, secret, status,
	last_test_result, last_test_at, last_test_error,
	created_at, updated_at
`

func scanIntegrationConnector(row pgx.Row) (repository.IntegrationConnector, error) {
	var (
		c             repository.IntegrationConnector
		typ           string
		status        string
		lastTestRes   string
		lastTestAt    *time.Time
		lastTestErr   string
		descNullable  string
		eventTypes    []string
		configBytes   []byte
		secretBytes   []byte
	)
	if err := row.Scan(
		&c.ID, &c.TenantID, &typ, &c.Name, &descNullable, &eventTypes,
		&configBytes, &secretBytes, &status,
		&lastTestRes, &lastTestAt, &lastTestErr,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return repository.IntegrationConnector{}, err
	}
	c.Type = repository.IntegrationConnectorType(typ)
	c.Description = descNullable
	c.EventTypes = eventTypes
	c.Config = json.RawMessage(configBytes)
	c.Secret = json.RawMessage(secretBytes)
	c.Status = repository.IntegrationConnectorStatus(status)
	c.LastTestResult = repository.IntegrationTestResult(lastTestRes)
	if lastTestAt != nil {
		t := *lastTestAt
		c.LastTestAt = &t
	}
	c.LastTestError = lastTestErr
	return c, nil
}

func (r *IntegrationConnectorRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.IntegrationConnector,
) (repository.IntegrationConnector, error) {
	if tenantID == uuid.Nil || c.Name == "" || !c.Type.IsValid() {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.Status == "" {
		c.Status = repository.IntegrationConnectorStatusActive
	}
	if c.LastTestResult == "" {
		c.LastTestResult = repository.IntegrationTestResultNever
	}
	if len(c.Config) == 0 {
		c.Config = json.RawMessage(`{}`)
	}
	if c.EventTypes == nil {
		// Postgres rejects NULL for TEXT[] NOT NULL.
		c.EventTypes = []string{}
	}
	var out repository.IntegrationConnector
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO integration_connectors
			    (id, tenant_id, type, name, description, event_types,
			     config, secret, status, last_test_result)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::text[],
			        $7::jsonb, $8::bytea, $9, $10)
			RETURNING ` + integrationConnectorSelectColumns
		row := tx.QueryRow(ctx, q,
			c.ID, tenantID, string(c.Type), c.Name, c.Description,
			c.EventTypes, []byte(c.Config), []byte(c.Secret),
			string(c.Status), string(c.LastTestResult),
		)
		var scanErr error
		out, scanErr = scanIntegrationConnector(row)
		if scanErr != nil {
			if isUniqueViolation(scanErr) {
				return repository.ErrConflict
			}
			if isCheckViolation(scanErr) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(scanErr) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert integration_connector: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IntegrationConnectorRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.IntegrationConnector, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	var out repository.IntegrationConnector
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + integrationConnectorSelectColumns + `
			FROM integration_connectors WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		var scanErr error
		out, scanErr = scanIntegrationConnector(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("select integration_connector: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IntegrationConnectorRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IntegrationConnector], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.IntegrationConnector]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.IntegrationConnector]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("integration_connectors", integrationConnectorSelectColumns, cur, page.Order, page.Limit)
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list integration_connectors: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.IntegrationConnector, 0, page.Limit)
		for rows.Next() {
			c, serr := scanIntegrationConnector(rows)
			if serr != nil {
				return fmt.Errorf("scan integration_connector: %w", serr)
			}
			items = append(items, c)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate integration_connectors: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

// Update applies a COALESCE-style partial update — empty string /
// nil slice / zero len blob means "keep existing". The Service
// layer is responsible for the read-modify-write semantics on
// secret rotation; Update only swaps non-empty fields.
func (r *IntegrationConnectorRepository) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	c repository.IntegrationConnector,
) (repository.IntegrationConnector, error) {
	if tenantID == uuid.Nil || c.ID == uuid.Nil {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	var out repository.IntegrationConnector
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE integration_connectors
			SET name        = COALESCE(NULLIF($2, ''), name),
			    description = COALESCE(NULLIF($3, ''), description),
			    event_types = COALESCE($4::text[], event_types),
			    config      = COALESCE($5::jsonb, config),
			    secret      = COALESCE($6::bytea, secret),
			    status      = COALESCE(NULLIF($7, ''), status)
			WHERE id = $1::uuid
			RETURNING ` + integrationConnectorSelectColumns
		var (
			eventTypes any
			config     any
			secret     any
		)
		if c.EventTypes != nil {
			eventTypes = c.EventTypes
		}
		if len(c.Config) > 0 {
			config = []byte(c.Config)
		}
		if len(c.Secret) > 0 {
			secret = []byte(c.Secret)
		}
		row := tx.QueryRow(ctx, q,
			c.ID, c.Name, c.Description, eventTypes, config, secret, string(c.Status),
		)
		var scanErr error
		out, scanErr = scanIntegrationConnector(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isUniqueViolation(scanErr) {
			return repository.ErrConflict
		}
		if isCheckViolation(scanErr) {
			return repository.ErrInvalidArgument
		}
		if scanErr != nil {
			return fmt.Errorf("update integration_connector: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IntegrationConnectorRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM integration_connectors WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete integration_connector: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *IntegrationConnectorRepository) SetStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.IntegrationConnectorStatus,
) (repository.IntegrationConnector, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	if status != repository.IntegrationConnectorStatusActive &&
		status != repository.IntegrationConnectorStatusDisabled {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	var out repository.IntegrationConnector
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE integration_connectors
			SET status = $2
			WHERE id = $1::uuid
			RETURNING ` + integrationConnectorSelectColumns
		row := tx.QueryRow(ctx, q, id, string(status))
		var scanErr error
		out, scanErr = scanIntegrationConnector(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isCheckViolation(scanErr) {
			return repository.ErrInvalidArgument
		}
		if scanErr != nil {
			return fmt.Errorf("set integration_connector status: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IntegrationConnectorRepository) RecordTestResult(
	ctx context.Context,
	tenantID, id uuid.UUID,
	result repository.IntegrationTestResult,
	at time.Time,
	lastErr string,
) (repository.IntegrationConnector, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	switch result {
	case repository.IntegrationTestResultSuccess,
		repository.IntegrationTestResultFailure,
		repository.IntegrationTestResultNever:
	default:
		return repository.IntegrationConnector{}, repository.ErrInvalidArgument
	}
	// Mirror memory: on SUCCESS clear last_test_error, on FAILURE
	// store it. NEVER preserves whatever was there.
	effectiveErr := ""
	if result == repository.IntegrationTestResultFailure {
		effectiveErr = lastErr
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var out repository.IntegrationConnector
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE integration_connectors
			SET last_test_result = $2,
			    last_test_at     = $3,
			    last_test_error  = $4
			WHERE id = $1::uuid
			RETURNING ` + integrationConnectorSelectColumns
		row := tx.QueryRow(ctx, q, id, string(result), at, effectiveErr)
		var scanErr error
		out, scanErr = scanIntegrationConnector(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("record integration_connector test result: %w", scanErr)
		}
		return nil
	})
	return out, err
}

// ListActive selects every active connector in the tenant whose
// event_types is empty (subscribe-to-all) or overlaps the supplied
// eventTypes (array `&&` operator). Ordering matches the
// webhook dispatcher for determinism.
func (r *IntegrationConnectorRepository) ListActive(
	ctx context.Context,
	tenantID uuid.UUID,
	eventTypes []string,
) ([]repository.IntegrationConnector, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	if eventTypes == nil {
		eventTypes = []string{}
	}
	var out []repository.IntegrationConnector
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// cardinality(event_types) = 0 → subscribe-to-all.
		const q = `
			SELECT ` + integrationConnectorSelectColumns + `
			FROM integration_connectors
			WHERE status = 'active'
			  AND (cardinality(event_types) = 0
			       OR event_types && $1::text[])
			ORDER BY created_at ASC, id ASC`
		rows, qerr := tx.Query(ctx, q, eventTypes)
		if qerr != nil {
			return fmt.Errorf("list active integration_connectors: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			c, serr := scanIntegrationConnector(rows)
			if serr != nil {
				return fmt.Errorf("scan active integration_connector: %w", serr)
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// -----------------------------------------------------------------
// IntegrationDeliveryRepository
// -----------------------------------------------------------------

// IntegrationDeliveryRepository owns integration_deliveries. The
// shape mirrors WebhookDeliveryRepository deliberately — same
// atomic-claim semantics, same stuck-row reaper window, same
// system-role bypass on the worker drain path.
type IntegrationDeliveryRepository struct{ s *Store }

const integrationDeliverySelectColumns = `
	id, tenant_id, connector_id, event_type, payload,
	status, attempts, last_attempt_at, last_error, next_retry_at,
	response_status, external_reference, created_at
`

func scanIntegrationDelivery(row pgx.Row) (repository.IntegrationDelivery, error) {
	var (
		d           repository.IntegrationDelivery
		payload     []byte
		status      string
		lastAttempt *time.Time
		lastErr     string
		respStatus  int32
		extRef      string
	)
	if err := row.Scan(
		&d.ID, &d.TenantID, &d.ConnectorID, &d.EventType, &payload,
		&status, &d.Attempts, &lastAttempt, &lastErr, &d.NextRetryAt,
		&respStatus, &extRef, &d.CreatedAt,
	); err != nil {
		return repository.IntegrationDelivery{}, err
	}
	d.Payload = json.RawMessage(payload)
	d.Status = repository.IntegrationDeliveryStatus(status)
	if lastAttempt != nil {
		t := *lastAttempt
		d.LastAttemptAt = &t
	}
	d.LastError = lastErr
	d.ResponseStatus = int(respStatus)
	d.ExternalReference = extRef
	return d, nil
}

func (r *IntegrationDeliveryRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	d repository.IntegrationDelivery,
) (repository.IntegrationDelivery, error) {
	if tenantID == uuid.Nil || d.ConnectorID == uuid.Nil || d.EventType == "" {
		return repository.IntegrationDelivery{}, repository.ErrInvalidArgument
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.Status == "" {
		d.Status = repository.IntegrationDeliveryStatusPending
	}
	if len(d.Payload) == 0 {
		d.Payload = json.RawMessage(`{}`)
	}
	if d.NextRetryAt.IsZero() {
		d.NextRetryAt = time.Now().UTC()
	}
	var out repository.IntegrationDelivery
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO integration_deliveries
			    (id, tenant_id, connector_id, event_type, payload,
			     status, attempts, next_retry_at, external_reference)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::jsonb,
			        $6, $7, $8, $9)
			RETURNING ` + integrationDeliverySelectColumns
		row := tx.QueryRow(ctx, q,
			d.ID, tenantID, d.ConnectorID, d.EventType, []byte(d.Payload),
			string(d.Status), d.Attempts, d.NextRetryAt, d.ExternalReference,
		)
		var scanErr error
		out, scanErr = scanIntegrationDelivery(row)
		if scanErr != nil {
			if isForeignKeyViolation(scanErr) {
				return repository.ErrNotFound
			}
			if isCheckViolation(scanErr) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert integration_delivery: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IntegrationDeliveryRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.IntegrationDelivery, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.IntegrationDelivery{}, repository.ErrInvalidArgument
	}
	var out repository.IntegrationDelivery
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + integrationDeliverySelectColumns + `
			FROM integration_deliveries WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		var scanErr error
		out, scanErr = scanIntegrationDelivery(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("select integration_delivery: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *IntegrationDeliveryRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	connectorID *uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IntegrationDelivery], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.IntegrationDelivery]{}, repository.ErrInvalidArgument
	}
	var cmp, dir string
	if page.Order == repository.SortAsc {
		cmp, dir = ">", "ASC"
	} else {
		cmp, dir = "<", "DESC"
	}
	args := []any{nil, nil, page.Limit, nil}
	if !cur.T.IsZero() || cur.I != uuid.Nil {
		args[0] = cur.T
		args[1] = cur.I
	}
	if connectorID != nil {
		args[3] = *connectorID
	}
	q := fmt.Sprintf(`
		SELECT %s
		FROM integration_deliveries
		WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
		  AND ($4::uuid IS NULL OR connector_id = $4::uuid)
		ORDER BY created_at %s, id %s
		LIMIT $3`, integrationDeliverySelectColumns, cmp, dir, dir)

	res := repository.PageResult[repository.IntegrationDelivery]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list integration_deliveries: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.IntegrationDelivery, 0, page.Limit)
		for rows.Next() {
			d, serr := scanIntegrationDelivery(rows)
			if serr != nil {
				return fmt.Errorf("scan integration_delivery: %w", serr)
			}
			items = append(items, d)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate integration_deliveries: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

func (r *IntegrationDeliveryRepository) UpdateStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.IntegrationDeliveryStatus,
	attempt int,
	lastErr string,
	responseStatus int,
	nextRetry time.Time,
	externalRef string,
) error {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// externalRef "" preserves existing value via COALESCE/NULLIF.
		const q = `
			UPDATE integration_deliveries
			SET status             = $2,
			    attempts           = $3,
			    last_error         = $4,
			    response_status    = $5,
			    next_retry_at      = $6,
			    last_attempt_at    = NOW(),
			    external_reference = COALESCE(NULLIF($7, ''), external_reference)
			WHERE id = $1::uuid`
		ct, err := tx.Exec(ctx, q,
			id, string(status), attempt, lastErr, int32(responseStatus),
			nextRetry, externalRef,
		)
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("update integration_delivery: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ListPending atomically claims a batch of due-for-retry
// deliveries using the same UPDATE...RETURNING + FOR UPDATE SKIP
// LOCKED pattern as WebhookDeliveryRepository.ListPending. See
// that method for the full architectural commentary; the
// invariants here are identical modulo the table name.
//
// Bypasses tenant RLS via withSystem because the delivery worker
// is a system-level component that must drain every tenant's
// queue in a single pass.
func (r *IntegrationDeliveryRepository) ListPending(
	ctx context.Context,
	limit int,
	processingTimeout time.Duration,
) ([]repository.IntegrationDelivery, error) {
	if limit <= 0 {
		limit = 32
	}
	var out []repository.IntegrationDelivery
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		var timeoutSeconds float64
		if processingTimeout > 0 {
			timeoutSeconds = processingTimeout.Seconds()
		}
		const q = `
			UPDATE integration_deliveries
			   SET status          = 'processing',
			       last_attempt_at = NOW()
			 WHERE id IN (
			     SELECT id FROM integration_deliveries
			      WHERE (
			            (status = 'pending' AND next_retry_at <= NOW())
			         OR (status = 'processing'
			             AND $2::float8 > 0
			             AND last_attempt_at IS NOT NULL
			             AND last_attempt_at < NOW() - make_interval(secs => $2::float8))
			            )
			      ORDER BY next_retry_at ASC, id ASC
			      LIMIT $1
			      FOR UPDATE SKIP LOCKED
			 )
			RETURNING ` + integrationDeliverySelectColumns
		rows, qerr := tx.Query(ctx, q, limit, timeoutSeconds)
		if qerr != nil {
			return fmt.Errorf("claim pending integration_deliveries: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			d, serr := scanIntegrationDelivery(rows)
			if serr != nil {
				return fmt.Errorf("scan claimed integration_delivery: %w", serr)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
