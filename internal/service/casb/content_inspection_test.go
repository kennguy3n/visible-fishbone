package casb_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

// --- fakes ---------------------------------------------------------------

type fakeConnectorRepo struct {
	conn   repository.CASBConnector
	getErr error
}

func (f *fakeConnectorRepo) Create(context.Context, uuid.UUID, repository.CASBConnector) (repository.CASBConnector, error) {
	return repository.CASBConnector{}, nil
}
func (f *fakeConnectorRepo) Get(_ context.Context, _, _ uuid.UUID) (repository.CASBConnector, error) {
	if f.getErr != nil {
		return repository.CASBConnector{}, f.getErr
	}
	return f.conn, nil
}
func (f *fakeConnectorRepo) List(context.Context, uuid.UUID, repository.Page) (repository.PageResult[repository.CASBConnector], error) {
	return repository.PageResult[repository.CASBConnector]{}, nil
}
func (f *fakeConnectorRepo) Update(context.Context, uuid.UUID, repository.CASBConnector) (repository.CASBConnector, error) {
	return repository.CASBConnector{}, nil
}
func (f *fakeConnectorRepo) UpdateSyncStatus(context.Context, uuid.UUID, uuid.UUID, repository.CASBConnectorStatus, time.Time) error {
	return nil
}
func (f *fakeConnectorRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error { return nil }

type fakeAudit struct {
	entries []repository.AuditEntry
}

func (f *fakeAudit) Append(_ context.Context, _ uuid.UUID, e repository.AuditEntry) (repository.AuditEntry, error) {
	f.entries = append(f.entries, e)
	return e, nil
}
func (f *fakeAudit) AppendGlobal(_ context.Context, e repository.AuditEntry) (repository.AuditEntry, error) {
	return e, nil
}
func (f *fakeAudit) List(context.Context, uuid.UUID, repository.AuditFilter, repository.Page) (repository.PageResult[repository.AuditEntry], error) {
	return repository.PageResult[repository.AuditEntry]{}, nil
}
func (f *fakeAudit) ListGlobal(context.Context, repository.AuditFilter, repository.Page) (repository.PageResult[repository.AuditEntry], error) {
	return repository.PageResult[repository.AuditEntry]{}, nil
}

// fakeClassifier flags content whose Source/Content matches a hit
// predicate, returning the configured action. It records every call so
// tests can assert which objects (and tenant) were classified.
type fakeClassifier struct {
	action  repository.DLPAction
	hitWhen func(dlp.ClassificationInput) bool
	failOn  string // substring of Source that should return an error
	calls   []dlp.ClassificationInput
	tenants []uuid.UUID
}

func (f *fakeClassifier) Classify(_ context.Context, tenantID uuid.UUID, in dlp.ClassificationInput) (dlp.ClassificationResult, error) {
	f.calls = append(f.calls, in)
	f.tenants = append(f.tenants, tenantID)
	if f.failOn != "" && strings.Contains(in.Metadata.Source, f.failOn) {
		return dlp.ClassificationResult{}, errors.New("boom")
	}
	if f.hitWhen != nil && f.hitWhen(in) {
		return dlp.ClassificationResult{
			Matches: []dlp.Match{{Pattern: "ssn", Confidence: 0.9}},
			Action:  f.action,
		}, nil
	}
	return dlp.ClassificationResult{}, nil
}

// inspectorPlugin satisfies both CASBConnectorPlugin and
// ContentInspector; objs is the canned stream ScanContent yields.
type inspectorPlugin struct {
	typ  repository.CASBConnectorType
	objs []casb.ContentObject
}

func (p *inspectorPlugin) Connect(context.Context, json.RawMessage, []byte) error { return nil }
func (p *inspectorPlugin) ListUsers(context.Context, json.RawMessage, []byte) ([]casb.SaaSUser, error) {
	return nil, nil
}
func (p *inspectorPlugin) ListActivity(context.Context, json.RawMessage, []byte, string) ([]casb.ActivityEvent, error) {
	return nil, nil
}
func (p *inspectorPlugin) AssessPosture(context.Context, json.RawMessage, []byte) (casb.PostureReport, error) {
	return casb.PostureReport{}, nil
}
func (p *inspectorPlugin) Test(context.Context, json.RawMessage, []byte) error { return nil }
func (p *inspectorPlugin) Type() repository.CASBConnectorType                  { return p.typ }
func (p *inspectorPlugin) ScanContent(ctx context.Context, _ json.RawMessage, _ []byte, opts casb.ContentScanOptions, yield func(context.Context, casb.ContentObject) error) error {
	for _, o := range p.objs {
		if err := yield(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

// plainPlugin satisfies CASBConnectorPlugin but NOT ContentInspector.
type plainPlugin struct{ typ repository.CASBConnectorType }

func (p *plainPlugin) Connect(context.Context, json.RawMessage, []byte) error { return nil }
func (p *plainPlugin) ListUsers(context.Context, json.RawMessage, []byte) ([]casb.SaaSUser, error) {
	return nil, nil
}
func (p *plainPlugin) ListActivity(context.Context, json.RawMessage, []byte, string) ([]casb.ActivityEvent, error) {
	return nil, nil
}
func (p *plainPlugin) AssessPosture(context.Context, json.RawMessage, []byte) (casb.PostureReport, error) {
	return casb.PostureReport{}, nil
}
func (p *plainPlugin) Test(context.Context, json.RawMessage, []byte) error { return nil }
func (p *plainPlugin) Type() repository.CASBConnectorType                  { return p.typ }

// --- helpers -------------------------------------------------------------

func obj(id, content string, modified time.Time) casb.ContentObject {
	return casb.ContentObject{
		ID:          id,
		Name:        id + ".txt",
		ContentType: "text/plain",
		ModifiedAt:  modified,
		Content:     []byte(content),
	}
}

func newRetroService(t *testing.T, plugin casb.CASBConnectorPlugin, classifier casb.ContentClassifier, enabled bool) (*casb.Service, *fakeAudit, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID := uuid.New()
	connID := uuid.New()
	typ := repository.CASBConnectorM365
	if plugin != nil {
		typ = plugin.Type()
	}
	repo := &fakeConnectorRepo{conn: repository.CASBConnector{
		ID:       connID,
		TenantID: tenantID,
		Type:     typ,
		Config:   json.RawMessage(`{}`),
	}}
	audit := &fakeAudit{}
	plugins := casb.PluginRegistry{}
	if plugin != nil {
		plugins[typ] = plugin
	}
	var opts []casb.Option
	if classifier != nil {
		opts = append(opts, casb.WithContentInspection(classifier, enabled))
	}
	svc := casb.New(repo, nil, nil, audit, plugins, nil, opts...)
	return svc, audit, tenantID, connID
}

// --- tests ---------------------------------------------------------------

func TestRetroScan_DisabledByDefault(t *testing.T) {
	t.Parallel()
	// No WithContentInspection option at all → default-OFF.
	svc, _, tenantID, connID := newRetroService(t,
		&inspectorPlugin{typ: repository.CASBConnectorM365}, nil, false)
	_, err := svc.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil)
	if !errors.Is(err, casb.ErrContentInspectionDisabled) {
		t.Fatalf("err = %v, want ErrContentInspectionDisabled", err)
	}
}

func TestRetroScan_EnabledFalseStillDisabled(t *testing.T) {
	t.Parallel()
	cls := &fakeClassifier{}
	svc, _, tenantID, connID := newRetroService(t,
		&inspectorPlugin{typ: repository.CASBConnectorM365}, cls, false)
	_, err := svc.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil)
	if !errors.Is(err, casb.ErrContentInspectionDisabled) {
		t.Fatalf("err = %v, want ErrContentInspectionDisabled", err)
	}
	if len(cls.calls) != 0 {
		t.Fatalf("classifier called %d times while disabled", len(cls.calls))
	}
}

func TestRetroScan_Unsupported(t *testing.T) {
	t.Parallel()
	cls := &fakeClassifier{}
	svc, _, tenantID, connID := newRetroService(t,
		&plainPlugin{typ: repository.CASBConnectorOkta}, cls, true)
	_, err := svc.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil)
	if !errors.Is(err, casb.ErrContentInspectionUnsupported) {
		t.Fatalf("err = %v, want ErrContentInspectionUnsupported", err)
	}
}

func TestRetroScan_HappyPath(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	plugin := &inspectorPlugin{
		typ: repository.CASBConnectorM365,
		objs: []casb.ContentObject{
			obj("a", "my ssn is 123-45-6789", now),
			obj("b", "nothing sensitive", now),
			obj("c", "another ssn here", now),
		},
	}
	cls := &fakeClassifier{
		action:  repository.DLPActionBlock,
		hitWhen: func(in dlp.ClassificationInput) bool { return strings.Contains(string(in.Content), "ssn") },
	}
	svc, audit, tenantID, connID := newRetroService(t, plugin, cls, true)

	res, err := svc.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil)
	if err != nil {
		t.Fatalf("RetroScanConnector: %v", err)
	}
	if res.ObjectsScanned != 3 {
		t.Fatalf("ObjectsScanned = %d, want 3", res.ObjectsScanned)
	}
	if res.ObjectsWithFindings != 2 {
		t.Fatalf("ObjectsWithFindings = %d, want 2", res.ObjectsWithFindings)
	}
	if res.TotalMatches != 2 {
		t.Fatalf("TotalMatches = %d, want 2", res.TotalMatches)
	}
	if res.HighestAction != repository.DLPActionBlock {
		t.Fatalf("HighestAction = %q, want block", res.HighestAction)
	}
	// Source attribution must be stamped for the DLP audit trail.
	wantSrc := "casb:m365:a"
	if cls.calls[0].Metadata.Source != wantSrc {
		t.Fatalf("Source = %q, want %q", cls.calls[0].Metadata.Source, wantSrc)
	}
	// Tenant isolation: every classify carries the connector's tenant.
	for _, tn := range cls.tenants {
		if tn != tenantID {
			t.Fatalf("classify tenant = %s, want %s", tn, tenantID)
		}
	}
	// A summary audit entry is written.
	if len(audit.entries) != 1 || audit.entries[0].Action != "casb.content_retro_scan" {
		t.Fatalf("audit entries = %+v", audit.entries)
	}
}

func TestRetroScan_MaxObjectsBudget(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	plugin := &inspectorPlugin{typ: repository.CASBConnectorM365}
	for i := 0; i < 10; i++ {
		plugin.objs = append(plugin.objs, obj(string(rune('a'+i)), "data", now))
	}
	cls := &fakeClassifier{}
	svc, _, tenantID, connID := newRetroService(t, plugin, cls, true)

	res, err := svc.RetroScanConnector(context.Background(), tenantID, connID,
		casb.ContentScanOptions{MaxObjects: 3}, nil)
	if err != nil {
		t.Fatalf("RetroScanConnector: %v", err)
	}
	if res.ObjectsScanned != 3 {
		t.Fatalf("ObjectsScanned = %d, want 3 (budget)", res.ObjectsScanned)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true")
	}
	if len(cls.calls) != 3 {
		t.Fatalf("classifier calls = %d, want 3", len(cls.calls))
	}
}

func TestRetroScan_SinceFilter(t *testing.T) {
	t.Parallel()
	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC()
	plugin := &inspectorPlugin{
		typ:  repository.CASBConnectorM365,
		objs: []casb.ContentObject{obj("old", "x", old), obj("new", "y", recent)},
	}
	cls := &fakeClassifier{}
	svc, _, tenantID, connID := newRetroService(t, plugin, cls, true)

	res, err := svc.RetroScanConnector(context.Background(), tenantID, connID,
		casb.ContentScanOptions{Since: recent.Add(-time.Hour)}, nil)
	if err != nil {
		t.Fatalf("RetroScanConnector: %v", err)
	}
	// Only the recent object passes the Since gate.
	if res.ObjectsScanned != 1 {
		t.Fatalf("ObjectsScanned = %d, want 1", res.ObjectsScanned)
	}
	if len(cls.calls) != 1 || cls.calls[0].Metadata.Source != "casb:m365:new" {
		t.Fatalf("unexpected classify calls: %+v", cls.calls)
	}
}

func TestRetroScan_ClassifyErrorIsResilient(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	plugin := &inspectorPlugin{
		typ: repository.CASBConnectorM365,
		objs: []casb.ContentObject{
			obj("good1", "ssn", now),
			obj("bad", "ssn", now),
			obj("good2", "ssn", now),
		},
	}
	cls := &fakeClassifier{
		action:  repository.DLPActionLog,
		hitWhen: func(dlp.ClassificationInput) bool { return true },
		failOn:  ":bad",
	}
	svc, _, tenantID, connID := newRetroService(t, plugin, cls, true)

	res, err := svc.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil)
	if err != nil {
		t.Fatalf("RetroScanConnector: %v", err)
	}
	if res.ObjectsScanned != 3 {
		t.Fatalf("ObjectsScanned = %d, want 3 (scan continued past error)", res.ObjectsScanned)
	}
	if res.ErrorCount != 1 || len(res.Errors) != 1 {
		t.Fatalf("ErrorCount = %d, Errors = %v, want 1", res.ErrorCount, res.Errors)
	}
	if res.ObjectsWithFindings != 2 {
		t.Fatalf("ObjectsWithFindings = %d, want 2 (the two that classified)", res.ObjectsWithFindings)
	}
}

func TestRetroScan_EmptyContentSkipsClassify(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	plugin := &inspectorPlugin{
		typ:  repository.CASBConnectorM365,
		objs: []casb.ContentObject{obj("empty", "", now), obj("full", "data", now)},
	}
	cls := &fakeClassifier{}
	svc, _, tenantID, connID := newRetroService(t, plugin, cls, true)

	res, err := svc.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil)
	if err != nil {
		t.Fatalf("RetroScanConnector: %v", err)
	}
	if res.ObjectsScanned != 2 {
		t.Fatalf("ObjectsScanned = %d, want 2", res.ObjectsScanned)
	}
	if len(cls.calls) != 1 {
		t.Fatalf("classifier calls = %d, want 1 (empty object skipped)", len(cls.calls))
	}
}

func TestRetroScan_ConnectorGetError(t *testing.T) {
	t.Parallel()
	cls := &fakeClassifier{}
	svc, _, tenantID, connID := newRetroService(t,
		&inspectorPlugin{typ: repository.CASBConnectorM365}, cls, true)
	// Swap in a repo that errors on Get by constructing a fresh service.
	repo := &fakeConnectorRepo{getErr: repository.ErrNotFound}
	svc2 := casb.New(repo, nil, nil, &fakeAudit{},
		casb.PluginRegistry{repository.CASBConnectorM365: &inspectorPlugin{typ: repository.CASBConnectorM365}},
		nil, casb.WithContentInspection(cls, true))
	_ = svc
	if _, err := svc2.RetroScanConnector(context.Background(), tenantID, connID, casb.ContentScanOptions{}, nil); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
