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

// WebhookEndpointRepository owns webhook_endpoints.
type WebhookEndpointRepository struct{ s *Store }

const webhookEndpointSelectColumns = `
	id, tenant_id, url, events, signing_secret, status, created_at, updated_at
`

func scanWebhookEndpoint(row pgx.Row) (repository.WebhookEndpoint, error) {
	var (
		ep     repository.WebhookEndpoint
		status string
	)
	if err := row.Scan(&ep.ID, &ep.TenantID, &ep.URL, &ep.Events, &ep.SigningSecret, &status, &ep.CreatedAt, &ep.UpdatedAt); err != nil {
		return repository.WebhookEndpoint{}, err
	}
	ep.Status = repository.WebhookEndpointStatus(status)
	return ep, nil
}

func (r *WebhookEndpointRepository) Create(ctx context.Context, tenantID uuid.UUID, ep repository.WebhookEndpoint) (repository.WebhookEndpoint, error) {
	if tenantID == uuid.Nil || ep.URL == "" || len(ep.SigningSecret) == 0 || len(ep.Events) == 0 {
		return repository.WebhookEndpoint{}, repository.ErrInvalidArgument
	}
	if ep.ID == uuid.Nil {
		ep.ID = uuid.New()
	}
	if ep.Status == "" {
		ep.Status = repository.WebhookEndpointStatusActive
	}
	var out repository.WebhookEndpoint
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO webhook_endpoints
			    (id, tenant_id, url, events, signing_secret, status)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
			RETURNING ` + webhookEndpointSelectColumns
		row := tx.QueryRow(ctx, q, ep.ID, tenantID, ep.URL, ep.Events, ep.SigningSecret, string(ep.Status))
		var err error
		out, err = scanWebhookEndpoint(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert webhook endpoint: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *WebhookEndpointRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.WebhookEndpoint, error) {
	var out repository.WebhookEndpoint
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + webhookEndpointSelectColumns + ` FROM webhook_endpoints WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		var err error
		out, err = scanWebhookEndpoint(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select webhook endpoint: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *WebhookEndpointRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.WebhookEndpoint], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.WebhookEndpoint]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.WebhookEndpoint]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("webhook_endpoints", webhookEndpointSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list webhook endpoints: %w", err)
		}
		defer rows.Close()
		items := make([]repository.WebhookEndpoint, 0, page.Limit)
		for rows.Next() {
			ep, err := scanWebhookEndpoint(rows)
			if err != nil {
				return fmt.Errorf("scan webhook endpoint: %w", err)
			}
			items = append(items, ep)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate webhook endpoints: %w", err)
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

func (r *WebhookEndpointRepository) Update(ctx context.Context, tenantID uuid.UUID, ep repository.WebhookEndpoint) (repository.WebhookEndpoint, error) {
	if tenantID == uuid.Nil || ep.ID == uuid.Nil {
		return repository.WebhookEndpoint{}, repository.ErrInvalidArgument
	}
	var out repository.WebhookEndpoint
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Use COALESCE-style partial update: empty strings / nil
		// arrays / empty bytes mean "keep existing".
		const q = `
			UPDATE webhook_endpoints
			SET url         = COALESCE(NULLIF($2, ''), url),
			    events      = COALESCE($3::text[], events),
			    status      = COALESCE(NULLIF($4, ''), status),
			    signing_secret = COALESCE($5::bytea, signing_secret)
			WHERE id = $1::uuid
			RETURNING ` + webhookEndpointSelectColumns
		var (
			events any
			secret any
		)
		if ep.Events != nil {
			events = ep.Events
		}
		if len(ep.SigningSecret) > 0 {
			secret = ep.SigningSecret
		}
		row := tx.QueryRow(ctx, q, ep.ID, ep.URL, events, string(ep.Status), secret)
		var scanErr error
		out, scanErr = scanWebhookEndpoint(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if isCheckViolation(scanErr) {
			return repository.ErrInvalidArgument
		}
		if scanErr != nil {
			return fmt.Errorf("update webhook endpoint: %w", scanErr)
		}
		return nil
	})
	return out, err
}

func (r *WebhookEndpointRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM webhook_endpoints WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete webhook endpoint: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ListActive selects all active endpoints subscribed to any of the
// given event types. Uses array overlap (`&&`) so the index on
// events stays usable (a GIN index on events would be ideal; for
// now the table-scan filter cost is acceptable until v2).
func (r *WebhookEndpointRepository) ListActive(ctx context.Context, tenantID uuid.UUID, eventTypes []string) ([]repository.WebhookEndpoint, error) {
	var out []repository.WebhookEndpoint
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT ` + webhookEndpointSelectColumns + `
			FROM webhook_endpoints
			WHERE status = 'active'
			  AND events && $1::text[]
			ORDER BY created_at ASC, id ASC`
		rows, err := tx.Query(ctx, q, eventTypes)
		if err != nil {
			return fmt.Errorf("list active endpoints: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			ep, err := scanWebhookEndpoint(rows)
			if err != nil {
				return fmt.Errorf("scan active endpoint: %w", err)
			}
			out = append(out, ep)
		}
		return rows.Err()
	})
	return out, err
}

// WebhookDeliveryRepository owns webhook_deliveries.
type WebhookDeliveryRepository struct{ s *Store }

const webhookDeliverySelectColumns = `
	id, tenant_id, endpoint_id, event_type, payload, status, attempts,
	last_attempt_at, last_error, next_retry_at, response_status, created_at
`

func scanWebhookDelivery(row pgx.Row) (repository.WebhookDelivery, error) {
	var (
		d           repository.WebhookDelivery
		payload     []byte
		lastAttempt *time.Time
		lastErr     *string
		respStatus  *int32
		status      string
	)
	if err := row.Scan(&d.ID, &d.TenantID, &d.EndpointID, &d.EventType,
		&payload, &status, &d.Attempts, &lastAttempt, &lastErr,
		&d.NextRetryAt, &respStatus, &d.CreatedAt); err != nil {
		return repository.WebhookDelivery{}, err
	}
	d.Payload = json.RawMessage(payload)
	d.Status = repository.WebhookDeliveryStatus(status)
	if lastAttempt != nil {
		t := *lastAttempt
		d.LastAttemptAt = &t
	}
	if lastErr != nil {
		d.LastError = *lastErr
	}
	if respStatus != nil {
		d.ResponseStatus = int(*respStatus)
	}
	return d, nil
}

func (r *WebhookDeliveryRepository) Create(ctx context.Context, tenantID uuid.UUID, d repository.WebhookDelivery) (repository.WebhookDelivery, error) {
	if tenantID == uuid.Nil || d.EndpointID == uuid.Nil || d.EventType == "" {
		return repository.WebhookDelivery{}, repository.ErrInvalidArgument
	}
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	if d.Status == "" {
		d.Status = repository.WebhookDeliveryStatusPending
	}
	if len(d.Payload) == 0 {
		d.Payload = json.RawMessage(`{}`)
	}
	if d.NextRetryAt.IsZero() {
		d.NextRetryAt = time.Now().UTC()
	}
	var out repository.WebhookDelivery
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO webhook_deliveries
			    (id, tenant_id, endpoint_id, event_type, payload,
			     status, attempts, next_retry_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::jsonb, $6, $7, $8)
			RETURNING ` + webhookDeliverySelectColumns
		row := tx.QueryRow(ctx, q, d.ID, tenantID, d.EndpointID, d.EventType,
			[]byte(d.Payload), string(d.Status), d.Attempts, d.NextRetryAt)
		var err error
		out, err = scanWebhookDelivery(row)
		if err != nil {
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert webhook delivery: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *WebhookDeliveryRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.WebhookDelivery, error) {
	var out repository.WebhookDelivery
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + webhookDeliverySelectColumns + ` FROM webhook_deliveries WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		var err error
		out, err = scanWebhookDelivery(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select webhook delivery: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *WebhookDeliveryRepository) List(ctx context.Context, tenantID uuid.UUID, endpointID *uuid.UUID, page repository.Page) (repository.PageResult[repository.WebhookDelivery], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.WebhookDelivery]{}, repository.ErrInvalidArgument
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
	if endpointID != nil {
		args[3] = *endpointID
	}
	q := fmt.Sprintf(`
		SELECT %s
		FROM webhook_deliveries
		WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
		  AND ($4::uuid IS NULL OR endpoint_id = $4::uuid)
		ORDER BY created_at %s, id %s
		LIMIT $3`, webhookDeliverySelectColumns, cmp, dir, dir)

	res := repository.PageResult[repository.WebhookDelivery]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list webhook deliveries: %w", err)
		}
		defer rows.Close()
		items := make([]repository.WebhookDelivery, 0, page.Limit)
		for rows.Next() {
			d, err := scanWebhookDelivery(rows)
			if err != nil {
				return fmt.Errorf("scan webhook delivery: %w", err)
			}
			items = append(items, d)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate webhook deliveries: %w", err)
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

func (r *WebhookDeliveryRepository) UpdateStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.WebhookDeliveryStatus,
	attempt int,
	lastErr string,
	responseStatus int,
	nextRetry time.Time,
) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE webhook_deliveries
			SET status          = $2,
			    attempts        = $3,
			    last_error      = NULLIF($4, ''),
			    response_status = NULLIF($5, 0),
			    next_retry_at   = $6,
			    last_attempt_at = NOW()
			WHERE id = $1::uuid`
		ct, err := tx.Exec(ctx, q, id, string(status), attempt, lastErr, int32(responseStatus), nextRetry)
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("update webhook delivery: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ListPending atomically claims a batch of due-for-retry
// deliveries. The implementation is a single `UPDATE ...
// RETURNING` statement that:
//
//  1. Selects up to `limit` rows whose status is 'pending' and
//     whose next_retry_at is due, OR rows stuck in 'processing'
//     whose last_attempt_at is older than `processingTimeout` ago
//     (the stuck-row reaper window — rescues rows whose previous
//     worker crashed between claim and UpdateStatus).
//  2. Holds row-level locks via `FOR UPDATE SKIP LOCKED` on the
//     inner SELECT so concurrent claim attempts skip each other's
//     rows rather than blocking.
//  3. Transitions the selected rows to 'processing' and stamps
//     last_attempt_at = NOW() in the same statement. This is the
//     critical invariant: the lock release at COMMIT no longer
//     matters because the rows are no longer in the candidate set
//     for any other worker — they're in 'processing', and the
//     UPDATE's WHERE filters that out (except after the stuck-row
//     window).
//  4. Returns the post-update row so the caller sees
//     status='processing' and can transition out via UpdateStatus
//     after dispatching the HTTP request.
//
// The previous implementation used a bare SELECT ... FOR UPDATE
// SKIP LOCKED and committed the transaction *before* the worker
// processed rows, releasing the locks immediately. That made the
// SKIP LOCKED hint cosmetic and produced duplicate deliveries
// under concurrent workers; see migrations/003_webhook_processing
// for the schema-level explanation.
//
// processingTimeout <= 0 disables the stuck-row reaper — only
// suitable for tests where the worker is guaranteed to either
// succeed or fail synchronously inside the same tick.
//
// Important: this method bypasses tenant RLS because the delivery
// worker is a system-level component that must drain every
// tenant's queue. RLS is restored implicitly for follow-up
// per-delivery UpdateStatus calls which pass tenantID and thus run
// with the appropriate sng.tenant_id GUC.
func (r *WebhookDeliveryRepository) ListPending(ctx context.Context, limit int, processingTimeout time.Duration) ([]repository.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 32
	}
	var out []repository.WebhookDelivery
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		// Two cases per the candidate WHERE:
		//   pending + due, OR processing + stuck > timeout ago.
		// We pass processingTimeout as a numeric seconds value
		// rather than embedding it as an interval literal so the
		// query plan is stable regardless of value.
		var timeoutSeconds float64
		if processingTimeout > 0 {
			timeoutSeconds = processingTimeout.Seconds()
		}
		const q = `
			UPDATE webhook_deliveries
			   SET status          = 'processing',
			       last_attempt_at = NOW()
			 WHERE id IN (
			     SELECT id FROM webhook_deliveries
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
			RETURNING ` + webhookDeliverySelectColumns
		rows, err := tx.Query(ctx, q, limit, timeoutSeconds)
		if err != nil {
			return fmt.Errorf("claim pending deliveries: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			d, err := scanWebhookDelivery(rows)
			if err != nil {
				return fmt.Errorf("scan claimed delivery: %w", err)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
