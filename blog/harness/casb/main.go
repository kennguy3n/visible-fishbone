// Command casb seeds a realistic per-tenant shadow-IT inventory and then
// drives the *real* CASB NoOps pipeline over it, so the blog's CASB
// screenshots and payloads are produced by the production classifier and
// audit trail — not hand-written fixtures.
//
// Flow (all through the same code paths the control plane runs):
//  1. Upsert a spread of discovered apps per tenant into
//     casb_discovered_apps (the inventory the shadow-IT discoverer would
//     build from SWG telemetry).
//  2. Construct casb.AppNoOpsEngine exactly as cmd/sng-control does
//     (NoOpsStore + discovered-app repo + tenant repo + audit log) and
//     call Reconcile() — the deterministic classifier categorises each
//     app, scores risk, recommends a sanction, and appends an immutable
//     audit action for every verdict.
//  3. Call RunDigests() so each tenant gets a per-tenant digest cursor.
//
// The engine here is recommend-only (no enforcer wired), matching the
// safe default posture: classify + audit + digest, never mutate traffic.
//
// DB access mirrors the control plane: connect as PG_USER and adopt the
// sng_app role per transaction (PgBouncerMode) so RLS / FORCE RLS applies
// exactly as in production.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// canonicalTenantID mirrors the seed harness so this tool targets the
// same four managed tenants.
var canonicalTenantID = map[string]string{
	"Acme Retail Group":     "92112770-7c0a-410b-b0f4-09dde70e063a",
	"Globex Health Systems": "3bd7bb7b-d48a-4569-8f97-46be31ae8e5a",
	"Initech Financial":     "b6520bda-e7bb-4af9-9c53-7b0051eae65b",
	"Umbrella Logistics":    "0c8d2d9d-896d-45b1-8001-6a6776f832b9",
}

// discoveredApp is one shadow-IT row to seed. Vendor/category are the
// identity labels the discoverer would attach; ActiveDevices is the
// windowed distinct-device count (the shadow-IT signal). RiskScore is the
// catalog/posture baseline when known.
type discoveredApp struct {
	name      string
	vendor    string
	category  string
	baseRisk  int
	devices   int
	firstSeen time.Duration // how long ago first seen
}

// perTenantApps is a realistic long-tail spread: sanctioned suites, a few
// risky file-share / AI tools, and obscure long-tail apps the catalog has
// never heard of (baseRisk 0) so the classifier's heuristics do the work.
var perTenantApps = map[string][]discoveredApp{
	"Acme Retail Group": {
		{"Microsoft 365", "Microsoft", "productivity", 10, 240, 240 * time.Hour},
		{"Slack", "Salesforce", "collaboration", 15, 180, 200 * time.Hour},
		{"Dropbox", "Dropbox", "cloud_storage", 55, 42, 90 * time.Hour},
		{"ChatGPT", "OpenAI", "ai_assistant", 60, 96, 72 * time.Hour},
		{"Grammarly", "Grammarly", "ai_writing", 45, 33, 60 * time.Hour},
		{"WeTransfer", "WeTransfer", "file_transfer", 70, 12, 36 * time.Hour},
		{"Notion", "Notion Labs", "productivity", 30, 58, 120 * time.Hour},
		{"Pastebin", "Pastebin", "code_paste", 75, 4, 18 * time.Hour},
		{"DeepL", "DeepL", "ai_translation", 40, 21, 48 * time.Hour},
	},
	"Globex Health Systems": {
		{"Microsoft 365", "Microsoft", "productivity", 10, 410, 300 * time.Hour},
		{"Epic MyChart", "Epic", "healthcare", 20, 380, 280 * time.Hour},
		{"Google Drive", "Google", "cloud_storage", 50, 64, 96 * time.Hour},
		{"ChatGPT", "OpenAI", "ai_assistant", 65, 140, 60 * time.Hour},
		{"Telegram", "Telegram", "messaging", 78, 9, 24 * time.Hour},
		{"MEGA", "MEGA", "cloud_storage", 82, 6, 20 * time.Hour},
		{"Claude", "Anthropic", "ai_assistant", 55, 47, 40 * time.Hour},
	},
	"Initech Financial": {
		{"Microsoft 365", "Microsoft", "productivity", 10, 150, 260 * time.Hour},
		{"Salesforce", "Salesforce", "crm", 18, 120, 240 * time.Hour},
		{"Box", "Box", "cloud_storage", 35, 70, 110 * time.Hour},
		{"ChatGPT", "OpenAI", "ai_assistant", 62, 64, 50 * time.Hour},
		{"AnonFiles", "AnonFiles", "file_transfer", 85, 3, 14 * time.Hour},
		{"Perplexity", "Perplexity", "ai_assistant", 48, 28, 36 * time.Hour},
	},
	"Umbrella Logistics": {
		{"Microsoft 365", "Microsoft", "productivity", 10, 95, 220 * time.Hour},
		{"Google Workspace", "Google", "productivity", 12, 88, 210 * time.Hour},
		{"Dropbox", "Dropbox", "cloud_storage", 55, 24, 80 * time.Hour},
		{"ChatGPT", "OpenAI", "ai_assistant", 60, 41, 44 * time.Hour},
		{"4shared", "4shared", "file_transfer", 80, 5, 16 * time.Hour},
	},
}

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	pool, err := openPool(ctx)
	if err != nil {
		fatal("open pool: " + err.Error())
	}
	defer pool.Close()

	rw := postgres.NewReadWritePool(postgres.ReadWritePoolConfig{
		Primary:       pool,
		AppRole:       envOr("PG_APP_ROLE", "sng_app"),
		PgBouncerMode: true,
		Logger:        logger,
	})
	store := postgres.NewStoreWithPool(rw)
	apps := store.NewCASBDiscoveredAppRepository()

	now := time.Now().UTC()
	totalApps := 0
	for name, list := range perTenantApps {
		idStr, ok := canonicalTenantID[name]
		if !ok {
			continue
		}
		tid := uuid.MustParse(idStr)
		for _, a := range list {
			risk := a.baseRisk
			dev := a.devices
			rec := repository.CASBDiscoveredApp{
				TenantID:          tid,
				Name:              a.name,
				Vendor:            a.vendor,
				Category:          a.category,
				RiskScore:         &risk,
				ActiveDeviceCount: &dev,
				FirstSeen:         now.Add(-a.firstSeen),
				LastSeen:          now,
			}
			if _, err := apps.Upsert(ctx, tid, rec); err != nil {
				fatal(fmt.Sprintf("upsert %s/%s: %v", name, a.name, err))
			}
			totalApps++
		}
		fmt.Printf("seeded %2d shadow-IT apps for %s\n", len(list), name)
	}

	// Drive the real NoOps pipeline: classify + audit, then digest.
	engine := casb.NewAppNoOpsEngine(
		postgres.NewCASBNoOpsStore(store),
		apps,
		store.NewTenantRepository(),
		logger,
	)
	engine.SetAuditLog(store.NewAuditLogRepository())

	if err := engine.Reconcile(ctx); err != nil {
		fatal("reconcile: " + err.Error())
	}
	fmt.Println("reconcile: classified + audited all discovered apps")

	if err := engine.RunDigests(ctx); err != nil {
		fatal("digests: " + err.Error())
	}
	fmt.Println("digests: per-tenant digest cursors built")

	fmt.Printf("OK — %d shadow-IT apps across %d tenants classified through the real NoOps engine\n",
		totalApps, len(perTenantApps))
}

func openPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOr("PG_HOST", "localhost"), envOr("PG_PORT", "5432"),
		envOr("PG_USER", "sng"), envOr("PG_PASSWORD", "sng"),
		envOr("PG_DATABASE", "sng"), envOr("PG_SSLMODE", "disable"),
	)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "casb-seed: "+msg)
	os.Exit(1)
}
