package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// errStopTest is a sentinel a collector returns to make a connector
// stop early, mirroring how the casb service stops once its object
// budget is reached.
var errStopTest = errors.New("stop")

type scanCollector struct {
	objs      []casb.ContentObject
	stopAfter int
}

func (c *scanCollector) yield(_ context.Context, o casb.ContentObject) error {
	c.objs = append(c.objs, o)
	if c.stopAfter > 0 && len(c.objs) >= c.stopAfter {
		return errStopTest
	}
	return nil
}

func (c *scanCollector) byID(id string) (casb.ContentObject, bool) {
	for _, o := range c.objs {
		if o.ID == id {
			return o, true
		}
	}
	return casb.ContentObject{}, false
}

// compile-time assertions that the five target connectors implement
// the content-inspection capability.
var (
	_ casb.ContentInspector = (*Box)(nil)
	_ casb.ContentInspector = (*M365)(nil)
	_ casb.ContentInspector = (*Google)(nil)
	_ casb.ContentInspector = (*Slack)(nil)
	_ casb.ContentInspector = (*Salesforce)(nil)
)

// --- Box -----------------------------------------------------------------

func boxScanServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "box-tok"})
		case r.URL.Path == "/2.0/folders/0/items":
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 2,
				"entries": []map[string]any{
					{"id": "10", "name": "sub", "type": "folder"},
					{"id": "100", "name": "root.txt", "type": "file", "size": 12, "modified_at": "2025-06-01T10:00:00Z"},
				},
			})
		case r.URL.Path == "/2.0/folders/10/items":
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 1,
				"entries": []map[string]any{
					{"id": "101", "name": "old.txt", "type": "file", "size": 5, "modified_at": "2020-01-01T00:00:00Z"},
				},
			})
		case r.URL.Path == "/2.0/files/100/content":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("root secret!"))
		case r.URL.Path == "/2.0/files/101/content":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("oldee"))
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func TestBox_ScanContent(t *testing.T) {
	srv := boxScanServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)

	var c scanCollector
	if err := b.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	if len(c.objs) != 2 {
		t.Fatalf("got %d objects, want 2", len(c.objs))
	}
	root, ok := c.byID("100")
	if !ok {
		t.Fatal("missing file 100")
	}
	if string(root.Content) != "root secret!" {
		t.Fatalf("content = %q", root.Content)
	}
	if root.ContentType != "text/plain" {
		t.Fatalf("content type = %q", root.ContentType)
	}
}

func TestBox_ScanContent_SinceFilter(t *testing.T) {
	srv := boxScanServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)

	since := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var c scanCollector
	if err := b.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{Since: since}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	// Only the 2025 file passes; the 2020 file in the subfolder is skipped.
	if len(c.objs) != 1 || c.objs[0].ID != "100" {
		t.Fatalf("unexpected objects: %+v", c.objs)
	}
}

func TestBox_ScanContent_ByteCap(t *testing.T) {
	srv := boxScanServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)

	var c scanCollector
	if err := b.ScanContent(context.Background(), cfg, sec,
		casb.ContentScanOptions{MaxBytesPerObject: 4}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	root, _ := c.byID("100")
	if string(root.Content) != "root" {
		t.Fatalf("content not capped to 4 bytes: %q", root.Content)
	}
}

func TestBox_ScanContent_StopEarly(t *testing.T) {
	srv := boxScanServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)

	c := scanCollector{stopAfter: 1}
	err := b.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield)
	if !errors.Is(err, errStopTest) {
		t.Fatalf("err = %v, want errStopTest", err)
	}
	if len(c.objs) != 1 {
		t.Fatalf("got %d objects after stop, want 1", len(c.objs))
	}
}

func TestBox_ScanContent_FetchErrorIsResilient(t *testing.T) {
	// File 100's content download 403s; the scan must surface that as a
	// per-object FetchErr and still yield the other file rather than abort.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "box-tok"})
		case r.URL.Path == "/2.0/folders/0/items":
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 2,
				"entries": []map[string]any{
					{"id": "100", "name": "denied.txt", "type": "file", "size": 1, "modified_at": "2025-06-01T10:00:00Z"},
					{"id": "200", "name": "ok.txt", "type": "file", "size": 2, "modified_at": "2025-06-01T10:00:00Z"},
				},
			})
		case r.URL.Path == "/2.0/files/100/content":
			http.Error(w, "forbidden", http.StatusForbidden)
		case r.URL.Path == "/2.0/files/200/content":
			w.Write([]byte("ok"))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)

	var c scanCollector
	if err := b.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent should not abort on a single 403, got: %v", err)
	}
	if len(c.objs) != 2 {
		t.Fatalf("got %d objects, want 2", len(c.objs))
	}
	denied, _ := c.byID("100")
	if denied.FetchErr == nil {
		t.Fatal("denied object should carry FetchErr")
	}
	ok, _ := c.byID("200")
	if ok.FetchErr != nil || string(ok.Content) != "ok" {
		t.Fatalf("ok object = %+v", ok)
	}
}

// --- M365 ----------------------------------------------------------------

func m365ScanServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "test-tok", "expires_in": 3600})
		case r.URL.Path == "/users":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{"id": "u1"}},
			})
		case r.URL.Path == "/users/u1/drive/root/children":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "d1", "name": "folder", "folder": map[string]any{"childCount": 1}},
					{"id": "f1", "name": "report.txt", "size": 9,
						"lastModifiedDateTime": "2025-06-01T10:00:00Z",
						"file":                 map[string]any{"mimeType": "text/plain"}},
				},
			})
		case r.URL.Path == "/users/u1/drive/items/d1/children":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "f2", "name": "nested.csv", "size": 4,
						"lastModifiedDateTime": "2025-06-02T10:00:00Z",
						"file":                 map[string]any{"mimeType": "text/csv"}},
				},
			})
		case r.URL.Path == "/users/u1/drive/items/f1/content":
			w.Write([]byte("graph ssn"))
		case r.URL.Path == "/users/u1/drive/items/f2/content":
			w.Write([]byte("a,b\n"))
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func TestM365_ScanContent(t *testing.T) {
	srv := m365ScanServer(t)
	defer srv.Close()
	m := newTestM365(t, srv)
	cfg, sec := m365TestCfg(t, srv.URL)

	var c scanCollector
	if err := m.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	if len(c.objs) != 2 {
		t.Fatalf("got %d objects, want 2", len(c.objs))
	}
	f1, ok := c.byID("f1")
	if !ok || string(f1.Content) != "graph ssn" || f1.Owner != "u1" {
		t.Fatalf("f1 = %+v", f1)
	}
	if _, ok := c.byID("f2"); !ok {
		t.Fatal("missing nested file f2 (folder not descended)")
	}
}

func TestM365_ScanContent_MissingDriveSkipped(t *testing.T) {
	// A user whose drive returns 404 must be skipped, not abort the scan.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "test-tok", "expires_in": 3600})
		case r.URL.Path == "/users":
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "u1"}}})
		case r.URL.Path == "/users/u1/drive/root/children":
			http.Error(w, `{"error":{"code":"itemNotFound"}}`, http.StatusNotFound)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	m := newTestM365(t, srv)
	cfg, sec := m365TestCfg(t, srv.URL)

	var c scanCollector
	if err := m.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent should skip missing drive, got: %v", err)
	}
	if len(c.objs) != 0 {
		t.Fatalf("got %d objects, want 0", len(c.objs))
	}
}

// --- Google --------------------------------------------------------------

func googleScanServer(t *testing.T, fx googleSAFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "minted-access-token", "expires_in": 3600})
		case strings.Contains(r.URL.Path, "/admin/directory/v1/users"):
			json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{{"primaryEmail": "alice@co.com"}},
			})
		case strings.HasSuffix(r.URL.Path, "/drive/v3/files"):
			json.NewEncoder(w).Encode(map[string]any{
				"files": []map[string]any{
					{"id": "doc1", "name": "Notes", "mimeType": "application/vnd.google-apps.document",
						"modifiedTime": "2025-06-01T10:00:00Z"},
					{"id": "bin1", "name": "data.bin", "mimeType": "application/octet-stream",
						"size": "7", "modifiedTime": "2025-06-02T10:00:00Z"},
					{"id": "fold", "name": "folder", "mimeType": "application/vnd.google-apps.folder"},
				},
			})
		case r.URL.Path == "/drive/v3/files/doc1/export":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("exported doc text"))
		case r.URL.Path == "/drive/v3/files/bin1":
			w.Write([]byte("binblob"))
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func TestGoogle_ScanContent(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleScanServer(t, fx)
	defer srv.Close()
	g := NewGoogle(srv.Client(), "test-ua")
	g.baseURL = srv.URL
	g.driveBaseURL = srv.URL
	g.tokenURL = srv.URL + "/token"
	cfg, sec := googleTestCfg(t, fx)

	var c scanCollector
	if err := g.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	// Native doc exported + binary downloaded; folder skipped.
	if len(c.objs) != 2 {
		t.Fatalf("got %d objects, want 2: %+v", len(c.objs), c.objs)
	}
	doc, ok := c.byID("doc1")
	if !ok || string(doc.Content) != "exported doc text" || doc.Owner != "alice@co.com" {
		t.Fatalf("doc1 = %+v", doc)
	}
	if doc.ContentType != "text/plain" {
		t.Fatalf("exported doc content type = %q, want text/plain", doc.ContentType)
	}
	bin, ok := c.byID("bin1")
	if !ok || string(bin.Content) != "binblob" {
		t.Fatalf("bin1 = %+v", bin)
	}
}

// --- Slack ---------------------------------------------------------------

func slackScanServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/conversations.list"):
			json.NewEncoder(w).Encode(map[string]any{
				"ok":       true,
				"channels": []map[string]any{{"id": "C1", "name": "general"}},
			})
		case strings.HasSuffix(r.URL.Path, "/api/conversations.history"):
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"messages": []map[string]any{
					{"type": "message", "ts": "1717238400.000100", "user": "U1", "text": "card 4111111111111111"},
					{"type": "message", "ts": "1717238500.000200", "user": "U2", "text": ""},
				},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func TestSlack_ScanContent(t *testing.T) {
	srv := slackScanServer(t)
	defer srv.Close()
	s := newTestSlack(t, srv)
	s.webBaseURL = srv.URL
	sec, _ := json.Marshal(SlackSecret{Token: "xoxp-test"})

	var c scanCollector
	if err := s.ScanContent(context.Background(), nil, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	// The empty message is skipped; only the card message yields.
	if len(c.objs) != 1 {
		t.Fatalf("got %d objects, want 1: %+v", len(c.objs), c.objs)
	}
	o := c.objs[0]
	if o.ID != "C1:1717238400.000100" || o.Owner != "U1" || string(o.Content) != "card 4111111111111111" {
		t.Fatalf("object = %+v", o)
	}
	if o.ContentType != "text/plain" {
		t.Fatalf("content type = %q", o.ContentType)
	}
	if o.ModifiedAt.IsZero() {
		t.Fatal("ModifiedAt not parsed from ts")
	}
}

// --- Salesforce ----------------------------------------------------------

func salesforceScanServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/oauth2/token"):
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "sf-tok",
				"instance_url": "http://" + r.Host,
			})
		case strings.Contains(r.URL.Path, "/query") && strings.Contains(r.URL.RawQuery, "ContentVersion"):
			json.NewEncoder(w).Encode(map[string]any{
				"done": true,
				"records": []map[string]any{
					{"Id": "cv1", "Title": "secrets", "FileExtension": "txt", "FileType": "TEXT",
						"ContentSize": 11, "LastModifiedDate": "2025-06-01T10:00:00.000+0000"},
				},
			})
		case r.URL.Path == "/services/data/v60.0/sobjects/ContentVersion/cv1/VersionData":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("ssn payload"))
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func TestSalesforce_ScanContent(t *testing.T) {
	srv := salesforceScanServer(t)
	defer srv.Close()
	sf := newTestSalesforce(t, srv)
	cfg, sec := salesforceTestCfg(t, srv.URL)

	var c scanCollector
	if err := sf.ScanContent(context.Background(), cfg, sec, casb.ContentScanOptions{}, c.yield); err != nil {
		t.Fatalf("ScanContent: %v", err)
	}
	if len(c.objs) != 1 {
		t.Fatalf("got %d objects, want 1", len(c.objs))
	}
	o := c.objs[0]
	if o.ID != "cv1" || o.Name != "secrets.txt" || string(o.Content) != "ssn payload" {
		t.Fatalf("object = %+v", o)
	}
}
