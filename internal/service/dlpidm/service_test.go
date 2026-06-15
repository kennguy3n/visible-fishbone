package dlpidm_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpidm"
)

func newService() *dlpidm.Service {
	return dlpidm.New(memory.NewDLPIDMRepository(memory.NewStore()), nil)
}

func TestService_RegisterDocument_StoresFingerprintsNotContent(t *testing.T) {
	t.Parallel()
	svc := newService()
	ctx := context.Background()
	tenantID := uuid.New()

	content := "the quick brown fox jumps over the lazy dog and then keeps running across the meadow"
	set, err := svc.RegisterDocument(ctx, tenantID, dlpidm.RegisterDocumentInput{
		Name:    "secret-contract",
		Content: content,
	})
	if err != nil {
		t.Fatalf("RegisterDocument: %v", err)
	}
	if len(set.Fingerprints) == 0 {
		t.Fatal("expected fingerprints")
	}
	if set.SourceBytes != int64(len(content)) {
		t.Fatalf("source bytes = %d, want %d", set.SourceBytes, len(content))
	}
	// The default fingerprint params must have been recorded.
	if set.ShingleSize != dlpidm.DefaultShingleSize || set.WindowSize != dlpidm.DefaultWindowSize {
		t.Fatalf("params not recorded: %+v", set)
	}
}

func TestService_RegisterDocument_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	svc := newService()
	_, err := svc.RegisterDocument(context.Background(), uuid.New(), dlpidm.RegisterDocumentInput{
		Name:    "   ",
		Content: "some content here that is long enough",
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestService_RegisterDocument_RejectsEmptyContent(t *testing.T) {
	t.Parallel()
	svc := newService()
	_, err := svc.RegisterDocument(context.Background(), uuid.New(), dlpidm.RegisterDocumentInput{
		Name:    "empty",
		Content: "   \n\t ",
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestService_RegisterDocument_RejectsBadParamOverride(t *testing.T) {
	t.Parallel()
	svc := newService()
	bad := 0
	_, err := svc.RegisterDocument(context.Background(), uuid.New(), dlpidm.RegisterDocumentInput{
		Name:        "bad-params",
		Content:     "content that is plenty long for fingerprinting",
		ShingleSize: &bad,
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestService_GetConfig_ReturnsDefaultsWhenUnset(t *testing.T) {
	t.Parallel()
	svc := newService()
	tenantID := uuid.New()
	cfg, err := svc.GetConfig(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	want := dlpidm.DefaultConfig(tenantID)
	if cfg != want {
		t.Fatalf("config = %+v, want defaults %+v", cfg, want)
	}
}

func TestService_PutConfig_RoundTrips(t *testing.T) {
	t.Parallel()
	svc := newService()
	ctx := context.Background()
	tenantID := uuid.New()

	in := dlpidm.ConfigInput{
		OCREnabled:             false,
		OCRMaxInputBytes:       2 << 20,
		OCRMaxDimension:        2048,
		IDMEnabled:             true,
		IDMSimilarityThreshold: 0.75,
		IDMShingleSize:         4,
		IDMWindowSize:          6,
		IDMMaxFingerprints:     1024,
	}
	if _, err := svc.PutConfig(ctx, tenantID, in); err != nil {
		t.Fatalf("PutConfig: %v", err)
	}
	cfg, err := svc.GetConfig(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.OCREnabled || cfg.IDMShingleSize != 4 || cfg.IDMSimilarityThreshold != 0.75 {
		t.Fatalf("config did not round-trip: %+v", cfg)
	}
}

func TestService_PutConfig_RejectsOutOfRange(t *testing.T) {
	t.Parallel()
	svc := newService()
	ctx := context.Background()
	tenantID := uuid.New()

	base := dlpidm.ConfigInput{
		OCREnabled:             true,
		OCRMaxInputBytes:       4 << 20,
		OCRMaxDimension:        4096,
		IDMEnabled:             true,
		IDMSimilarityThreshold: 0.8,
		IDMShingleSize:         5,
		IDMWindowSize:          8,
		IDMMaxFingerprints:     2048,
	}
	cases := map[string]func(*dlpidm.ConfigInput){
		"threshold too high":  func(c *dlpidm.ConfigInput) { c.IDMSimilarityThreshold = 1.5 },
		"threshold zero":      func(c *dlpidm.ConfigInput) { c.IDMSimilarityThreshold = 0 },
		"ocr bytes too small": func(c *dlpidm.ConfigInput) { c.OCRMaxInputBytes = 1 },
		"dimension too big":   func(c *dlpidm.ConfigInput) { c.OCRMaxDimension = 100000 },
		"shingle too big":     func(c *dlpidm.ConfigInput) { c.IDMShingleSize = 1000 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			mutate(&in)
			if _, err := svc.PutConfig(ctx, tenantID, in); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestService_Status_ReflectsSetsAndConfig(t *testing.T) {
	t.Parallel()
	svc := newService()
	ctx := context.Background()
	tenantID := uuid.New()

	if _, err := svc.RegisterDocument(ctx, tenantID, dlpidm.RegisterDocumentInput{
		Name:    "doc-1",
		Content: strings.Repeat("alpha beta gamma delta epsilon ", 10),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	status, err := svc.Status(ctx, tenantID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Stats.SetCount != 1 {
		t.Fatalf("set count = %d, want 1", status.Stats.SetCount)
	}
	if status.Config.TenantID != tenantID {
		t.Fatalf("config tenant = %v, want %v", status.Config.TenantID, tenantID)
	}
}

func TestService_UpdateSet_RejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	svc := newService()
	ctx := context.Background()
	tenantID := uuid.New()

	set, err := svc.RegisterDocument(ctx, tenantID, dlpidm.RegisterDocumentInput{
		Name:    "patchme",
		Content: "content long enough to fingerprint cleanly here",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.UpdateSet(ctx, tenantID, set.ID, repository.IDMFingerprintSetPatch{}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}
