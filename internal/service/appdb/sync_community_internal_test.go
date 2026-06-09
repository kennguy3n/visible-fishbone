package appdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// buildFeedArchive packs the given (path -> file body) entries into a
// gzip-compressed tar, the on-the-wire shape Shallalist / UT1 publish.
func buildFeedArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write tar header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write tar body %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func newSyncerWithService(t *testing.T) (*Syncer, *Service) {
	t.Helper()
	store := memory.NewStore()
	svc := New(
		memory.NewAppRegistryRepository(store),
		memory.NewAppRegistryOverrideRepository(store),
		memory.NewAuditLogRepository(store),
		nil,
	)
	clock := func() time.Time { return time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) }
	svc.SetClock(clock)
	syncer := NewSyncer(svc, nil)
	syncer.SetClock(clock)
	return syncer, svc
}

func TestCanonicalCategoryDomain(t *testing.T) {
	cases := map[string]string{
		"  Example.COM ":       "example.com",
		"*.gambling.example":   "gambling.example",
		"# a comment":          "",
		";also a comment":      "",
		"":                     "",
		"localhost":            "", // no dot -> not a hostname
		"http://evil.test/x":   "", // scheme + path -> rejected
		"host with space.test": "",
		"a.b.c.example.org":    "a.b.c.example.org",
	}
	for in, want := range cases {
		if got := canonicalCategoryDomain(in); got != want {
			t.Errorf("canonicalCategoryDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapCommunityCategoryAndSanitize(t *testing.T) {
	cases := map[string]string{
		"adv":          "advertising",
		"porn":         "adult.content",
		"adult":        "adult.content",
		"gamble":       "gambling",
		"malware":      "security.threat",
		"socialnet":    "social.media",
		"weird-cat!":   "community.weird_cat",
		"":             "community.uncategorised",
		"Imagehosting": "community.imagehosting", // mixed case feed dir
	}
	for in, want := range cases {
		if got := mapCommunityCategory(in); got != want {
			t.Errorf("mapCommunityCategory(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCommunityCategoryFeed(t *testing.T) {
	archive := buildFeedArchive(t, map[string]string{
		"BL/adv/domains":     "doubleclick.net\n# comment\nads.example.com\n\n",
		"BL/porn/domains":    "xxx.example\n",
		"BL/porn/urls":       "xxx.example/path\n", // urls file ignored
		"BL/adv/expressions": "ad-regex\n",         // non-domains file ignored
		"BL/README":          "not a category\n",
	})
	got, err := ParseCommunityCategoryFeed(archive)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got["adv"]) != 2 {
		t.Errorf("adv domains = %v, want 2 entries", got["adv"])
	}
	if len(got["porn"]) != 1 || got["porn"][0] != "xxx.example" {
		t.Errorf("porn domains = %v, want [xxx.example]", got["porn"])
	}
	if _, ok := got["bl"]; ok {
		t.Errorf("unexpected category from README file: %v", got)
	}
}

func TestParseCommunityCategoryFeedRejectsNonGzip(t *testing.T) {
	if _, err := ParseCommunityCategoryFeed([]byte("not a gzip archive")); err == nil {
		t.Fatal("expected error parsing non-gzip body")
	}
}

func TestIngestCommunityFeed_CreatesAndMerges(t *testing.T) {
	syncer, svc := newSyncerWithService(t)
	ctx := context.Background()

	archive := buildFeedArchive(t, map[string]string{
		"BL/adv/domains":   "doubleclick.net\nads.example.com\n",
		"BL/adult/domains": "xxx.example\n",
		"BL/porn/domains":  "nsfw.example\n", // adult + porn both -> adult.content
	})
	results, err := syncer.IngestCommunityFeed(ctx, CommunityFeedShallalist, archive)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// Canonical categories: advertising, adult.content (created).
	byCat := map[string]CommunityIngestResult{}
	for _, r := range results {
		byCat[r.Category] = r
	}
	if r := byCat["advertising"]; !r.Created || r.DomainsAfter != 2 {
		t.Errorf("advertising result = %+v, want created with 2 domains", r)
	}
	if r := byCat["adult.content"]; !r.Created || r.DomainsAfter != 2 {
		t.Errorf("adult.content result = %+v, want created with 2 domains (adult+porn unioned)", r)
	}

	adult, err := svc.apps.GetByName(ctx, "community:shallalist:adult.content")
	if err != nil {
		t.Fatalf("getbyname: %v", err)
	}
	if adult.TrafficClass != repository.TrafficClassInspectFull {
		t.Errorf("traffic class = %q, want inspect_full", adult.TrafficClass)
	}
	if adult.Vendor != CommunityFeedShallalist || adult.Category != "adult.content" {
		t.Errorf("row metadata = vendor %q category %q", adult.Vendor, adult.Category)
	}

	// Re-ingest unchanged data: must be a no-op (no Created/Updated).
	results2, err := syncer.IngestCommunityFeed(ctx, CommunityFeedShallalist, archive)
	if err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	for _, r := range results2 {
		if r.Created || r.Updated {
			t.Errorf("re-ingest of unchanged data mutated %q: %+v", r.Category, r)
		}
	}

	// Ingest a superset for advertising: additive growth, Updated set.
	grow := buildFeedArchive(t, map[string]string{
		"BL/adv/domains": "doubleclick.net\nads.example.com\nnewtracker.example\n",
	})
	results3, err := syncer.IngestCommunityFeed(ctx, CommunityFeedShallalist, grow)
	if err != nil {
		t.Fatalf("grow ingest: %v", err)
	}
	if len(results3) != 1 || !results3[0].Updated || results3[0].DomainsAfter != 3 {
		t.Errorf("grow result = %+v, want updated with 3 domains", results3)
	}
}

func TestIngestCommunityFeed_UnknownFeedRejected(t *testing.T) {
	syncer, _ := newSyncerWithService(t)
	if _, err := syncer.IngestCommunityFeed(context.Background(), "bogus", nil); err == nil {
		t.Fatal("expected error for unknown feed name")
	}
}

func TestAggregateCategoryFeedback_WeightingAndDedup(t *testing.T) {
	syncer, svc := newSyncerWithService(t)
	ctx := context.Background()

	// Operator-curated row (authoritative).
	if _, err := svc.CreateApp(ctx, repository.AppRegistry{
		Name:         "Office",
		Vendor:       "microsoft",
		TrafficClass: repository.TrafficClassTrustedDirect,
		Scope:        repository.AppRegistryScopeGlobal,
		Domains:      []string{"*.office.com", "outlook.office.com"},
		Category:     "business.saas",
		IsSystem:     true,
	}); err != nil {
		t.Fatalf("create operator app: %v", err)
	}
	// Community row that also labels office.com but with a different
	// (lower-trust) category — the operator label must win.
	if _, err := svc.CreateApp(ctx, repository.AppRegistry{
		Name:         "community:shallalist:advertising",
		Vendor:       CommunityFeedShallalist,
		TrafficClass: repository.TrafficClassInspectFull,
		Scope:        repository.AppRegistryScopeGlobal,
		Domains:      []string{"office.com", "doubleclick.net"},
		Category:     "advertising",
		IsSystem:     true,
	}); err != nil {
		t.Fatalf("create community app: %v", err)
	}
	// Uncategorised row contributes nothing.
	if _, err := svc.CreateApp(ctx, repository.AppRegistry{
		Name:         "Unlabeled",
		Vendor:       "test",
		TrafficClass: repository.TrafficClassInspectFull,
		Scope:        repository.AppRegistryScopeGlobal,
		Domains:      []string{"mystery.example"},
		IsSystem:     true,
	}); err != nil {
		t.Fatalf("create unlabeled app: %v", err)
	}

	corpus, err := syncer.AggregateCategoryFeedback(ctx)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}

	labels := map[string]CategoryLabel{}
	for _, l := range corpus.Labels {
		labels[l.Domain] = l
	}
	// office.com is labelled by both; operator (weight 1.0) wins.
	if got := labels["office.com"]; got.Category != "business.saas" || got.Weight != categoryLabelWeightOperator {
		t.Errorf("office.com label = %+v, want business.saas @ operator weight", got)
	}
	// "*.office.com" canonicalises to office.com — must not double-count.
	if _, ok := labels["*.office.com"]; ok {
		t.Errorf("wildcard domain leaked into corpus: %v", corpus.Labels)
	}
	// doubleclick.net only from the community feed.
	if got := labels["doubleclick.net"]; got.Category != "advertising" || got.Weight != categoryLabelWeightCommunity {
		t.Errorf("doubleclick.net label = %+v, want advertising @ community weight", got)
	}
	// Unlabeled row excluded.
	if _, ok := labels["mystery.example"]; ok {
		t.Errorf("uncategorised domain leaked into corpus: %v", corpus.Labels)
	}
	if corpus.PerCategory["business.saas"] != 2 {
		t.Errorf("per-category business.saas = %d, want 2 (office.com + outlook.office.com)", corpus.PerCategory["business.saas"])
	}
	// Labels must be sorted by domain for reproducible training input.
	for i := 1; i < len(corpus.Labels); i++ {
		if corpus.Labels[i-1].Domain > corpus.Labels[i].Domain {
			t.Fatalf("labels not sorted by domain: %v", corpus.Labels)
		}
	}
}

func TestIsCommunityFeedVendor(t *testing.T) {
	for _, v := range []string{"shallalist", "UT1", " ut1 "} {
		if !isCommunityFeedVendor(v) {
			t.Errorf("isCommunityFeedVendor(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"microsoft", "", "operator"} {
		if isCommunityFeedVendor(v) {
			t.Errorf("isCommunityFeedVendor(%q) = true, want false", v)
		}
	}
}
