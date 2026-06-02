package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// MaxBulkDevices caps the number of devices per bulk operation.
const MaxBulkDevices = 1000

// BulkEnrollRequest describes a batch enrollment token generation.
type BulkEnrollRequest struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Count    int       `json:"count"`
}

// BulkRevokeRequest describes a batch device revocation.
type BulkRevokeRequest struct {
	TenantID  uuid.UUID   `json:"tenant_id"`
	DeviceIDs []uuid.UUID `json:"device_ids"`
}

// BulkPostureRequest describes a batch posture policy update.
type BulkPostureRequest struct {
	TenantID  uuid.UUID       `json:"tenant_id"`
	DeviceIDs []uuid.UUID     `json:"device_ids"`
	Config    json.RawMessage `json:"config"`
}

// BulkResult summarises a bulk operation outcome.
type BulkResult struct {
	Total     int      `json:"total"`
	Succeeded int      `json:"succeeded"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

// DeviceCSVRow represents one device in CSV import/export format.
type DeviceCSVRow struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// BulkDeviceService handles batch device operations.
type BulkDeviceService struct {
	devices repository.DeviceRepository
	tokens  repository.ClaimTokenRepository
	enrolls repository.DeviceEnrollmentRepository
	logger  *slog.Logger
	nowFunc func() time.Time
}

// NewBulkDeviceService returns a ready-to-use bulk device service.
func NewBulkDeviceService(
	devices repository.DeviceRepository,
	tokens repository.ClaimTokenRepository,
	enrolls repository.DeviceEnrollmentRepository,
	logger *slog.Logger,
) *BulkDeviceService {
	if logger == nil {
		logger = slog.Default()
	}
	return &BulkDeviceService{
		devices: devices,
		tokens:  tokens,
		enrolls: enrolls,
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
}

// SetNowFunc overrides the clock for testing.
func (s *BulkDeviceService) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		s.nowFunc = fn
	}
}

// BulkGenerateTokens creates N claim tokens for a tenant.
func (s *BulkDeviceService) BulkGenerateTokens(
	ctx context.Context,
	tenantID uuid.UUID,
	count int,
	ttl time.Duration,
) (BulkResult, []repository.ClaimToken, error) {
	if count <= 0 || count > MaxBulkDevices {
		return BulkResult{}, nil, fmt.Errorf("count must be 1-%d: %w", MaxBulkDevices, repository.ErrInvalidArgument)
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := s.nowFunc()
	result := BulkResult{Total: count}
	var tokens []repository.ClaimToken
	for i := 0; i < count; i++ {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("token %d: rng: %v", i, err))
			continue
		}
		hash := sha256.Sum256(raw)
		token := repository.ClaimToken{
			TenantID:  tenantID,
			TokenHash: hash[:],
			ExpiresAt: now.Add(ttl),
		}
		created, err := s.tokens.Create(ctx, tenantID, token)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("token %d: %v", i, err))
			continue
		}
		result.Succeeded++
		tokens = append(tokens, created)
	}
	return result, tokens, nil
}

// BulkRevoke revokes a list of device enrollments.
func (s *BulkDeviceService) BulkRevoke(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceIDs []uuid.UUID,
) (BulkResult, error) {
	if len(deviceIDs) > MaxBulkDevices {
		return BulkResult{}, fmt.Errorf("max %d devices per request: %w", MaxBulkDevices, repository.ErrInvalidArgument)
	}
	result := BulkResult{Total: len(deviceIDs)}
	for _, did := range deviceIDs {
		if err := s.enrolls.UpdateEnrollmentStatus(ctx, tenantID, did, repository.EnrollmentStatusRevoked); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("device %s: %v", did, err))
			continue
		}
		result.Succeeded++
	}
	return result, nil
}

// ExportCSV writes device inventory as CSV.
func (s *BulkDeviceService) ExportCSV(
	ctx context.Context,
	tenantID uuid.UUID,
	devices []repository.Device,
) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"device_id", "name", "platform", "status", "created_at"}); err != nil {
		return nil, err
	}
	for _, d := range devices {
		if d.TenantID != tenantID {
			continue
		}
		if err := w.Write([]string{
			d.ID.String(),
			d.Name,
			string(d.Platform),
			string(d.Status),
			d.CreatedAt.Format(time.RFC3339),
		}); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// ImportCSV parses a CSV of device rows.
func (s *BulkDeviceService) ImportCSV(r io.Reader) ([]DeviceCSVRow, error) {
	reader := csv.NewReader(r)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, nil
	}
	// Skip header row.
	var rows []DeviceCSVRow
	for _, rec := range records[1:] {
		if len(rec) < 5 {
			continue
		}
		rows = append(rows, DeviceCSVRow{
			DeviceID:  rec[0],
			Name:      rec[1],
			Platform:  rec[2],
			Status:    rec[3],
			CreatedAt: rec[4],
		})
	}
	if len(rows) > MaxBulkDevices {
		return nil, fmt.Errorf("CSV exceeds max %d rows: %w", MaxBulkDevices, repository.ErrInvalidArgument)
	}
	return rows, nil
}
