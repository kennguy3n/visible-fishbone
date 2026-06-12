package casb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

// API-CASB content inspection upgrades the discovery-shaped
// connectors (service.go enumerates users/activity/posture) with a
// data-aware capability: a connector that implements [ContentInspector]
// can stream the *content* of the objects, files, and messages it
// hosts so the control plane can run each through the existing DLP
// classifier (internal/service/dlp) and surface findings.
//
// Design constraints this file deliberately honours:
//
//   - Default-OFF. Content inspection is never triggered by the
//     out-of-band [Service.SyncConnector] sweep, the shadow-IT
//     discovery loop, or any background task. It runs only when an
//     operator explicitly calls [Service.RetroScanConnector], and even
//     then only when the service was constructed with
//     [WithContentInspection] and an enabled gate. A deployment that
//     does not opt in behaves exactly as before.
//   - Streaming + bounded. Connectors yield one object at a time
//     (page-by-page) rather than buffering an entire SaaS estate, and
//     every fetch is capped at [ContentScanOptions.MaxBytesPerObject].
//     This keeps memory flat across 5000 tenants regardless of how
//     much data a tenant stores.
//   - Reuse, don't reimplement. Detection is delegated wholesale to
//     the tenant's enabled DLP policies via [ContentClassifier]; this
//     package never ships its own regex/fingerprint logic. The DLP
//     service already persists a per-match audit trail keyed by
//     [dlp.ClassificationMetadata.Source], so findings are durable
//     without a new table.

// DefaultMaxContentBytes bounds how many bytes of a single object are
// fetched and classified when a caller does not specify a cap. 5 MiB
// comfortably covers documents, spreadsheets, and chat transcripts
// while protecting the control plane from pulling a multi-gigabyte
// blob into memory.
const DefaultMaxContentBytes int64 = 5 << 20

// ContentObject is a single SaaS object (a file, document, or chat
// message) whose content is submitted to the DLP classifier. It is
// the content-inspection analogue of [SaaSUser] / [ActivityEvent]:
// connectors translate provider-specific payloads into this shape so
// the service stays provider-agnostic.
type ContentObject struct {
	// ID is the provider-stable object identifier (Box file id,
	// Graph driveItem id, Slack message ts, Salesforce ContentVersion
	// id, ...). It is used for source attribution in the DLP audit
	// trail, so it must be stable across scans.
	ID string
	// Name is a human-readable label (filename, channel/message
	// reference) surfaced to operators reviewing findings.
	Name string
	// Owner is the object's owning principal (email/login) when the
	// provider exposes it; empty otherwise.
	Owner string
	// ContentType is the MIME type when known (helps DLP route
	// content-type-specific rules); empty when the provider does not
	// report one.
	ContentType string
	// SizeBytes is the provider-reported size before any truncation,
	// for observability; the classified slice may be shorter when the
	// per-object byte cap trims it.
	SizeBytes int64
	// ModifiedAt is the object's last-modified time, used by the
	// service to honour [ContentScanOptions.Since] as a defence in
	// depth even when the connector already filtered server-side.
	ModifiedAt time.Time
	// Content is the (possibly truncated) object bytes to classify.
	Content []byte
}

// ContentScanOptions configures a content-inspection pass. The zero
// value scans every object with the default per-object byte cap.
type ContentScanOptions struct {
	// Since restricts the scan to objects modified at or after this
	// instant. The zero time means "no lower bound" — a full
	// retro-scan of every existing object.
	Since time.Time
	// MaxObjects caps how many objects are fetched and classified in
	// one pass (0 = unlimited). It bounds the cost of an operator-
	// triggered retro-scan over a large estate.
	MaxObjects int
	// MaxBytesPerObject caps the bytes fetched per object. Values <= 0
	// fall back to [DefaultMaxContentBytes].
	MaxBytesPerObject int64
}

// normalized returns a copy with defaults applied so connectors can
// rely on a sane MaxBytesPerObject without re-checking.
func (o ContentScanOptions) normalized() ContentScanOptions {
	if o.MaxBytesPerObject <= 0 {
		o.MaxBytesPerObject = DefaultMaxContentBytes
	}
	return o
}

// ContentInspector is the optional capability a CASB connector
// implements to support API-CASB content inspection. It is kept
// separate from [CASBConnectorPlugin] so that discovery-only
// connectors (cloud consoles, IdPs, HCM) need not implement it and
// the service can feature-detect support with a type assertion.
//
// Implementations MUST:
//   - stream objects page-by-page, invoking yield exactly once per
//     fetched object, instead of buffering the whole result set;
//   - stop and return ctx.Err() promptly when ctx is cancelled;
//   - propagate the error yield returns (the service uses it to stop
//     early once [ContentScanOptions.MaxObjects] is reached);
//   - cap each object's fetched bytes at opts.MaxBytesPerObject;
//   - be safe for concurrent use across tenants (stateless; all
//     per-tenant state arrives via config/secret), mirroring the
//     discovery methods.
type ContentInspector interface {
	ScanContent(
		ctx context.Context,
		config json.RawMessage,
		secret []byte,
		opts ContentScanOptions,
		yield func(context.Context, ContentObject) error,
	) error
}

// ContentClassifier is the slice of the DLP service the CASB content
// inspector depends on. Declaring it here (rather than importing the
// concrete *dlp.Service everywhere) keeps the dependency narrow and
// makes the classifier trivially mockable in tests. *dlp.Service
// satisfies it.
type ContentClassifier interface {
	Classify(ctx context.Context, tenantID uuid.UUID, input dlp.ClassificationInput) (dlp.ClassificationResult, error)
}

// Option configures optional [Service] dependencies. It mirrors the
// functional-option style used by the DLP service.
type Option func(*Service)

// WithContentInspection wires the DLP classifier the CASB content
// inspector submits object content to, and the master gate that arms
// [Service.RetroScanConnector]. Both are required: a service built
// without this option, or with enabled=false, rejects retro-scan
// requests with [ErrContentInspectionDisabled], guaranteeing the
// feature is default-OFF.
func WithContentInspection(classifier ContentClassifier, enabled bool) Option {
	return func(s *Service) {
		s.classifier = classifier
		s.inspectionEnabled = enabled
	}
}

var (
	// ErrContentInspectionDisabled is returned when a retro-scan is
	// requested but the feature was not armed via
	// [WithContentInspection] (the default-OFF posture).
	ErrContentInspectionDisabled = errors.New("casb: content inspection is disabled")
	// ErrContentInspectionUnsupported is returned when the target
	// connector's plugin does not implement [ContentInspector]
	// (e.g. an IdP or cloud-console connector with no object content).
	ErrContentInspectionUnsupported = errors.New("casb: connector does not support content inspection")

	// errStopScan is the internal sentinel the per-object yield uses to
	// tell a connector to stop once MaxObjects has been reached. It is
	// never surfaced to callers.
	errStopScan = errors.New("casb: content scan object budget reached")
)

// maxScanErrors bounds how many per-object failures a single
// [ContentScanResult] retains. A pathological connector or a transient
// provider outage must not let the error slice grow without bound; the
// count keeps incrementing so operators still see the true magnitude.
const maxScanErrors = 100

// ContentScanResult summarizes one content-inspection pass. Per-match
// detail is persisted by the DLP service itself (keyed by Source);
// this struct gives the caller an at-a-glance outcome and a bounded
// sample of non-fatal errors.
type ContentScanResult struct {
	ConnectorID         uuid.UUID            `json:"connector_id"`
	ConnectorType       string               `json:"connector_type"`
	ObjectsScanned      int                  `json:"objects_scanned"`
	ObjectsWithFindings int                  `json:"objects_with_findings"`
	TotalMatches        int                  `json:"total_matches"`
	HighestAction       repository.DLPAction `json:"highest_action,omitempty"`
	// ErrorCount is the total number of objects that failed to fetch
	// or classify; Errors holds the first [maxScanErrors] of them.
	ErrorCount int       `json:"error_count"`
	Errors     []string  `json:"errors,omitempty"`
	Truncated  bool      `json:"truncated"`
	ScannedAt  time.Time `json:"scanned_at"`
}

// RetroScanConnector runs the existing-object retro-scan for a single
// connector: it fetches each object's content through the connector's
// [ContentInspector] and submits it to the tenant's DLP policies. It
// is the deliberately explicit, operator-triggered entrypoint for
// content inspection — nothing in the normal sync path calls it.
//
// The scan is resilient: a single object that fails to fetch or
// classify is recorded in the result and skipped rather than aborting
// the whole pass, so one corrupt object cannot starve a tenant's scan.
// The DLP service persists a match record (with Source
// "casb:<type>:<object-id>") for every policy hit, so findings are
// durable without this package adding a table.
func (svc *Service) RetroScanConnector(
	ctx context.Context,
	tenantID, connectorID uuid.UUID,
	opts ContentScanOptions,
	actorID *uuid.UUID,
) (ContentScanResult, error) {
	if !svc.inspectionEnabled || svc.classifier == nil {
		return ContentScanResult{}, ErrContentInspectionDisabled
	}
	c, err := svc.connectors.Get(ctx, tenantID, connectorID)
	if err != nil {
		return ContentScanResult{}, err
	}
	plugin, ok := svc.plugins[c.Type]
	if !ok {
		return ContentScanResult{}, fmt.Errorf("%w: no plugin for type %q", ErrConnectorFailed, c.Type)
	}
	inspector, ok := plugin.(ContentInspector)
	if !ok {
		return ContentScanResult{}, fmt.Errorf("%w: %q", ErrContentInspectionUnsupported, c.Type)
	}

	opts = opts.normalized()
	result := ContentScanResult{
		ConnectorID:   connectorID,
		ConnectorType: string(c.Type),
		ScannedAt:     svc.nowFunc(),
	}

	yield := func(ctx context.Context, obj ContentObject) error {
		// Defence in depth: honour Since even if the connector did not
		// (or could not) filter server-side.
		if !opts.Since.IsZero() && !obj.ModifiedAt.IsZero() && obj.ModifiedAt.Before(opts.Since) {
			return nil
		}
		if len(obj.Content) == 0 {
			// Nothing to classify (empty file / empty message). Count
			// it as scanned so object budgets and totals stay honest.
			result.ObjectsScanned++
			return svc.scanBudgetCheck(&result, opts)
		}

		res, cerr := svc.classifier.Classify(ctx, tenantID, dlp.ClassificationInput{
			ContentType: obj.ContentType,
			Content:     obj.Content,
			Metadata: dlp.ClassificationMetadata{
				Filename: obj.Name,
				Source:   contentSource(c.Type, obj.ID),
				User:     obj.Owner,
			},
		})
		result.ObjectsScanned++
		if cerr != nil {
			svc.recordScanError(&result, fmt.Sprintf("object %s: classify: %v", obj.ID, cerr))
			return svc.scanBudgetCheck(&result, opts)
		}
		if len(res.Matches) > 0 {
			result.ObjectsWithFindings++
			result.TotalMatches += len(res.Matches)
			result.HighestAction = higherDLPAction(result.HighestAction, res.Action)
		}
		return svc.scanBudgetCheck(&result, opts)
	}

	scanErr := inspector.ScanContent(ctx, c.Config, c.Secret, opts, yield)
	if scanErr != nil && !errors.Is(scanErr, errStopScan) {
		// A hard connector error (auth, network) aborts the pass; the
		// partial result is still returned for observability.
		svc.logger.WarnContext(ctx, "casb: content retro-scan failed",
			slog.String("connector_id", connectorID.String()),
			slog.String("connector_type", string(c.Type)),
			slog.Any("error", scanErr))
		svc.logContentScanAudit(ctx, tenantID, actorID, connectorID, result, scanErr)
		return result, fmt.Errorf("%w: scan content: %v", ErrConnectorFailed, scanErr)
	}

	svc.logContentScanAudit(ctx, tenantID, actorID, connectorID, result, nil)
	return result, nil
}

// scanBudgetCheck returns errStopScan once the per-pass object budget
// is exhausted so the connector stops paging; nil otherwise.
func (svc *Service) scanBudgetCheck(result *ContentScanResult, opts ContentScanOptions) error {
	if opts.MaxObjects > 0 && result.ObjectsScanned >= opts.MaxObjects {
		result.Truncated = true
		return errStopScan
	}
	return nil
}

// recordScanError increments the error count and retains a bounded
// sample of error strings.
func (svc *Service) recordScanError(result *ContentScanResult, msg string) {
	result.ErrorCount++
	if len(result.Errors) < maxScanErrors {
		result.Errors = append(result.Errors, msg)
	}
}

// contentSource builds the Source attribution string the DLP service
// stamps on every persisted match, so findings are traceable back to
// the exact connector and object that produced them.
func contentSource(t repository.CASBConnectorType, objectID string) string {
	return fmt.Sprintf("casb:%s:%s", t, objectID)
}

// higherDLPAction picks the stricter of two DLP actions, mirroring the
// DLP service's own action-priority ordering
// (log < redact < encrypt < block) so the result's HighestAction
// reflects the most severe policy that fired across the whole pass.
func higherDLPAction(a, b repository.DLPAction) repository.DLPAction {
	if dlpActionPriority(a) >= dlpActionPriority(b) {
		return a
	}
	return b
}

func dlpActionPriority(a repository.DLPAction) int {
	switch a {
	case repository.DLPActionLog:
		return 1
	case repository.DLPActionRedact:
		return 2
	case repository.DLPActionEncrypt:
		return 3
	case repository.DLPActionBlock:
		return 4
	default:
		return 0
	}
}

// logContentScanAudit writes a single summary entry to the existing
// audit log. Per-match detail already lives in the DLP match trail;
// this records that a scan happened, by whom, and its aggregate
// outcome.
func (svc *Service) logContentScanAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	connectorID uuid.UUID,
	result ContentScanResult,
	scanErr error,
) {
	details := map[string]any{
		"connector_type":        result.ConnectorType,
		"objects_scanned":       result.ObjectsScanned,
		"objects_with_findings": result.ObjectsWithFindings,
		"total_matches":         result.TotalMatches,
		"error_count":           result.ErrorCount,
		"truncated":             result.Truncated,
	}
	if result.HighestAction != "" {
		details["highest_action"] = string(result.HighestAction)
	}
	if scanErr != nil {
		details["error"] = scanErr.Error()
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.content_retro_scan",
		"casb_connector", &connectorID, details)
}
