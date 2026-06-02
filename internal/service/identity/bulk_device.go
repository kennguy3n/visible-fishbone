package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
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

// BulkTokenResult pairs a persisted token with its one-time plaintext.
type BulkTokenResult struct {
	Token     repository.ClaimToken `json:"token"`
	Plaintext string                `json:"plaintext"`
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
// Each returned BulkTokenResult includes the plaintext (shown once).
func (s *BulkDeviceService) BulkGenerateTokens(
	ctx context.Context,
	tenantID uuid.UUID,
	count int,
	ttl time.Duration,
) (BulkResult, []BulkTokenResult, error) {
	if count <= 0 || count > MaxBulkDevices {
		return BulkResult{}, nil, fmt.Errorf("count must be 1-%d: %w", MaxBulkDevices, repository.ErrInvalidArgument)
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := s.nowFunc()
	result := BulkResult{Total: count}
	var tokens []BulkTokenResult
	for i := 0; i < count; i++ {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("token %d: rng: %v", i, err))
			continue
		}
		plaintext := base64.RawURLEncoding.EncodeToString(raw)
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
		tokens = append(tokens, BulkTokenResult{Token: created, Plaintext: plaintext})
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
	now := s.nowFunc()
	for _, did := range deviceIDs {
		if err := s.enrolls.UpdateEnrollmentStatus(ctx, tenantID, did, repository.EnrollmentStatusRevoked); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("device %s: %v", did, err))
			continue
		}
		if err := s.enrolls.RevokeAllCertificates(ctx, tenantID, did, now); err != nil {
			s.logger.Warn("bulk revoke: certificate revocation failed",
				"device_id", did, "tenant_id", tenantID, "error", err)
		}
		result.Succeeded++
	}
	return result, nil
}

// ExportCSV writes device inventory as CSV.
func (s *BulkDeviceService) ExportCSV(
	_ context.Context,
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

// ImportCSV parses a CSV of device inventory rows and persists each
// as a device for the tenant. It is the symmetric counterpart to
// ExportCSV: every successfully parsed row results in a created
// device. Per-row failures (malformed platform, repository errors)
// are isolated and reported in the returned BulkResult so a single
// bad row does not abort the whole import.
func (s *BulkDeviceService) ImportCSV(
	ctx context.Context,
	tenantID uuid.UUID,
	r io.Reader,
) (BulkResult, error) {
	rows, malformed, err := parseDeviceCSV(r)
	if err != nil {
		return BulkResult{}, err
	}
	// Total counts every data row in the CSV (header excluded),
	// including rows that could not be parsed at all. Malformed rows
	// (wrong column count) are reported as failures so the caller is
	// never silently shorted records.
	result := BulkResult{Total: len(rows) + len(malformed)}
	result.Failed += len(malformed)
	result.Errors = append(result.Errors, malformed...)
	for _, dr := range rows {
		dev, derr := deviceFromCSVRow(dr.row)
		if derr != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("row %d: %v", dr.line, derr))
			continue
		}
		if _, cerr := s.devices.Create(ctx, tenantID, dev); cerr != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("row %d: %v", dr.line, cerr))
			continue
		}
		result.Succeeded++
	}
	return result, nil
}

// csvDataRow pairs a parsed CSV row with its 1-based data-row number
// (header excluded) so per-row errors reference the original line.
type csvDataRow struct {
	line int
	row  DeviceCSVRow
}

// parseDeviceCSV reads device rows from CSV, skipping the header. It
// returns the well-formed rows alongside per-row error messages for
// rows that have too few columns to parse, so callers can surface
// them instead of dropping them silently.
func parseDeviceCSV(r io.Reader) ([]csvDataRow, []string, error) {
	reader := csv.NewReader(r)
	// Allow a variable column count so a single short/long row is
	// reported per-row instead of aborting the entire import.
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, nil, nil
	}
	// Skip header row; number remaining rows from 1.
	var rows []csvDataRow
	var malformed []string
	for i, rec := range records[1:] {
		line := i + 1
		if len(rec) < 5 {
			malformed = append(malformed, fmt.Sprintf("row %d: expected 5 columns, got %d", line, len(rec)))
			continue
		}
		rows = append(rows, csvDataRow{
			line: line,
			row: DeviceCSVRow{
				DeviceID:  rec[0],
				Name:      rec[1],
				Platform:  rec[2],
				Status:    rec[3],
				CreatedAt: rec[4],
			},
		})
	}
	if len(rows)+len(malformed) > MaxBulkDevices {
		return nil, nil, fmt.Errorf("CSV exceeds max %d rows: %w", MaxBulkDevices, repository.ErrInvalidArgument)
	}
	return rows, malformed, nil
}

// deviceFromCSVRow builds a Device from one inventory row. The
// device_id column is honoured only when it is a valid UUID;
// foreign identifiers from other systems are dropped so the
// repository assigns a fresh primary key. Platform is required and
// validated; status defaults to pending when omitted.
func deviceFromCSVRow(row DeviceCSVRow) (repository.Device, error) {
	platform := repository.DevicePlatform(strings.ToLower(strings.TrimSpace(row.Platform)))
	if !isKnownPlatform(platform) {
		return repository.Device{}, fmt.Errorf("invalid platform %q: %w", row.Platform, repository.ErrInvalidArgument)
	}
	dev := repository.Device{
		Name:     strings.TrimSpace(row.Name),
		Platform: platform,
	}
	if id, perr := uuid.Parse(strings.TrimSpace(row.DeviceID)); perr == nil {
		dev.ID = id
	}
	if st := repository.DeviceStatus(strings.ToLower(strings.TrimSpace(row.Status))); st != "" {
		if !isKnownStatus(st) {
			return repository.Device{}, fmt.Errorf("invalid status %q: %w", row.Status, repository.ErrInvalidArgument)
		}
		dev.Status = st
	}
	return dev, nil
}

func isKnownPlatform(p repository.DevicePlatform) bool {
	switch p {
	case repository.DevicePlatformWindows,
		repository.DevicePlatformMacOS,
		repository.DevicePlatformLinux,
		repository.DevicePlatformIOS,
		repository.DevicePlatformAndroid:
		return true
	default:
		return false
	}
}

func isKnownStatus(s repository.DeviceStatus) bool {
	switch s {
	case repository.DeviceStatusPending,
		repository.DeviceStatusActive,
		repository.DeviceStatusSuspended,
		repository.DeviceStatusDeleted:
		return true
	default:
		return false
	}
}
