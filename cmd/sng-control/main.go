// Command sng-control is the ShieldNet Gateway control-plane service
// entrypoint. It loads configuration from the environment, opens
// connections to NATS and PostgreSQL, and serves the operator HTTP
// API alongside health and readiness probes.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/apikey"
	"github.com/kennguy3n/visible-fishbone/internal/service/appdb"
	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
	"github.com/kennguy3n/visible-fishbone/internal/service/rbac"
	"github.com/kennguy3n/visible-fishbone/internal/service/site"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
	chwriter "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/clickhouse"
	telreplay "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/replay"
	s3writer "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/s3"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
	"github.com/kennguy3n/visible-fishbone/internal/service/webhook"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sng-control: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := newLogger(&cfg)
	logger.Info("sng-control: starting",
		slog.String("app", cfg.AppName),
		slog.String("env", string(cfg.Environment)),
		slog.String("version", cfg.Telemetry.ServiceVersion))

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := openPostgres(rootCtx, &cfg, logger)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()

	nc, err := openNATS(rootCtx, &cfg, logger)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer func() {
		if err := nc.Drain(); err != nil {
			logger.Warn("sng-control: nats drain error", slog.Any("error", err))
		}
	}()

	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("jetstream: %w", err)
	}
	// Use a generous overall budget (numStreams * per-stream timeout * 2)
	// so even a fully-degraded NATS that consumes the per-stream budget
	// can still report errors per-stream rather than collapsing the
	// whole bootstrap on a single context deadline.
	streams := sngnats.DefaultStreams(&cfg.NATS)
	overall := time.Duration(len(streams)*2) * cfg.NATS.RequestTimeout
	if overall <= 0 {
		overall = 30 * time.Second
	}
	ensureCtx, ensureCancel := context.WithTimeout(rootCtx, overall)
	err = sngnats.EnsureStreams(ensureCtx, js, streams, cfg.NATS.RequestTimeout)
	ensureCancel()
	if err != nil {
		return fmt.Errorf("ensure streams: %w", err)
	}
	logger.Info("sng-control: jetstream streams ensured",
		slog.String("prefix", cfg.NATS.StreamPrefix))

	health := handler.NewHealth(2 * time.Second)
	health.Register("postgres", handler.PingerFunc(func(ctx context.Context) error {
		return pool.Ping(ctx)
	}))
	health.Register("nats", handler.PingerFunc(func(_ context.Context) error {
		if nc.Status() != nats.CONNECTED {
			return fmt.Errorf("nats not connected: status=%s", nc.Status())
		}
		return nil
	}))

	// Telemetry pipeline — hot-path ClickHouse writer + cold-path
	// S3 archive + DLQ replay worker. Wired here so the consumer
	// goroutine starts draining SNG_TELEMETRY as soon as we have
	// connectivity to NATS + storage. The publisher used by the
	// DLQ machinery is shared with the replay worker so a
	// successful replay re-publish goes through the same retry +
	// dedup configuration. Building the worker BEFORE buildRouter
	// lets the operator-admin replay endpoint live on the same
	// authed API mux as the rest of the operator surface.
	telPublisher := sngnats.NewPublisher(js, &cfg.NATS, cfg.AppName+"/telemetry")
	telReplay := telreplay.New(js, telPublisher, cfg.NATS.StreamPrefix,
		cfg.TelemetryAnalytics.ReplayDurable, logger)

	router, webhookWorker, appRegHandler, appSyncer, err := buildRouter(&cfg, logger, pool, health, telReplay)
	if err != nil {
		return fmt.Errorf("build router: %w", err)
	}

	// Start the webhook delivery worker before the HTTP server so
	// queued deliveries from a previous run start draining
	// immediately on boot. Stopped during shutdown below.
	if err := webhookWorker.Start(rootCtx); err != nil {
		return fmt.Errorf("start webhook worker: %w", err)
	}

	// Launch the periodic app-registry sync loop. The Syncer pulls
	// vendor-published endpoint lists (Microsoft 365, Google IP
	// ranges, AWS, etc.) on the cadence configured by
	// APP_REGISTRY_SYNC_INTERVAL (default 24h, matching
	// docs/TRAFFIC_CLASSIFICATION.md §8). Set
	// APP_REGISTRY_SYNC_ENABLED=false to skip the background loop
	// — the admin-triggered `POST /admin/app-registry/sync`
	// endpoint stays functional regardless, so an operator can
	// force a sync on demand. We do not wait for the goroutine on
	// shutdown: Syncer.Run returns the moment rootCtx is
	// cancelled, and an in-flight HTTP fetch will be unblocked by
	// the same ctx that gates the rest of the process.
	if cfg.AppRegistry.SyncEnabled {
		go appSyncer.Run(rootCtx, cfg.AppRegistry.SyncInterval)
		logger.Info("sng-control: app-registry sync loop started",
			slog.Duration("interval", cfg.AppRegistry.SyncInterval))
	} else {
		logger.Info("sng-control: app-registry sync loop disabled (APP_REGISTRY_SYNC_ENABLED=false)")
	}

	rawTelShutdown, chWriter, err := startTelemetry(rootCtx, &cfg, logger, js, telPublisher)
	if err != nil {
		return fmt.Errorf("start telemetry: %w", err)
	}
	// Wire the ClickHouse writer into the AppRegistry handler so
	// the /app-registry/stats endpoint can serve per-class
	// distributions. When ClickHouse is not configured, chWriter
	// is nil and the handler keeps returning 503 on /stats.
	if chWriter != nil {
		appRegHandler.SetStats(clickhouseStatsAdapter{w: chWriter})
	}
	// Wrap startTelemetry's shutdown in a sync.Once so the bounded
	// explicit call (with shutdownCtx) wins and the safety-net
	// defer (with context.Background()) becomes a no-op rather
	// than racing a second close against an already-stopped
	// ClickHouse connection. The defer still covers early-return
	// paths between here and the explicit shutdown below.
	var telShutdownOnce sync.Once
	telShutdown := func(ctx context.Context) error {
		var shutdownErr error
		telShutdownOnce.Do(func() { shutdownErr = rawTelShutdown(ctx) })
		return shutdownErr
	}
	defer func() {
		if err := telShutdown(context.Background()); err != nil {
			logger.Error("telemetry shutdown failed", slog.Any("error", err))
		}
	}()

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr(),
		Handler:           router,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("sng-control: http server listening", slog.String("addr", cfg.HTTP.Addr()))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case <-rootCtx.Done():
		logger.Info("sng-control: shutdown signal received")
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("sng-control: http shutdown error", slog.Any("error", err))
	}

	if err := webhookWorker.Stop(shutdownCtx); err != nil {
		logger.Warn("sng-control: webhook worker shutdown error", slog.Any("error", err))
	}

	if err := telShutdown(shutdownCtx); err != nil {
		logger.Warn("sng-control: telemetry shutdown error", slog.Any("error", err))
	}

	logger.Info("sng-control: stopped")
	return nil
}

// buildRouter wires every repository / service / handler against
// the Postgres pool and returns the composed HTTP handler plus the
// webhook delivery worker (so main can start/stop it alongside the
// HTTP server). Kept in one place so the dependency graph is
// readable; production wiring + tests share the same factory.
//
// An error from this constructor is fatal at boot: a missing
// policy signer would silently emit unsigned bundles that edge
// agents (correctly) refuse, breaking enforcement everywhere.
func buildRouter(
	cfg *config.Config,
	logger *slog.Logger,
	pool *pgxpool.Pool,
	health *handler.Health,
	replay *telreplay.Worker,
) (http.Handler, *webhook.DeliveryWorker, *handler.AppRegistryHandler, *appdb.Syncer, error) {
	store := postgres.NewStore(pool)

	tenantRepo := store.NewTenantRepository()
	siteRepo := store.NewSiteRepository()
	deviceRepo := store.NewDeviceRepository()
	roleRepo := store.NewRoleRepository()
	claimRepo := store.NewClaimTokenRepository()
	auditRepo := store.NewAuditLogRepository()
	policyRepo := store.NewPolicyRepository()
	policyKeyRepo := store.NewPolicySigningKeyRepository()
	webhookEndpointRepo := store.NewWebhookEndpointRepository()
	webhookDeliveryRepo := store.NewWebhookDeliveryRepository()
	apiKeyRepo := store.NewTenantAPIKeyRepository()
	appRepo := store.NewAppRegistryRepository()
	appOverrideRepo := store.NewAppRegistryOverrideRepository()

	tenantSvc := tenant.New(tenantRepo, auditRepo, logger)
	siteSvc := site.New(siteRepo, auditRepo, logger)
	identitySvc := identity.New(deviceRepo, claimRepo, auditRepo, logger)
	rbacSvc := rbac.New(roleRepo, auditRepo, logger)
	auditSvc := audit.New(auditRepo)
	apiKeySvc := apikey.New(apiKeyRepo, auditRepo,
		apikey.WithLogger(logger),
		apikey.WithMaxActiveKeys(cfg.Auth.APIKeyMaxActivePerTenant),
	)

	// Policy signing — PR8 introduces two operator-controlled
	// alternates to the PR7 DB-backed KeyService:
	//   1. POLICY_SIGNING_KEY_PATH: when set, every bundle is
	//      signed with the file-loaded Ed25519 key (single key,
	//      all tenants). Rotation is out-of-band (CD pipeline
	//      replaces the file + restarts the process). The
	//      DB-backed KeyService is still constructed so the
	//      rotation / public-key endpoints keep working for
	//      operators that swap modes between restarts.
	//   2. POLICY_KEY_WRAP_MASTER_*: when set, the KeyService
	//      wraps each tenant's seed under AES-256-GCM at rest
	//      so the policy_signing_keys.private_key column carries
	//      ciphertext (defence in depth on top of TDE / disk
	//      encryption).
	// They are independent — you can use either, both, or
	// neither. The policy.Service surface (Signer interface) is
	// the same in all cases.
	keyOpts := []policy.KeyOption{}
	if master, err := loadPolicyKeyWrapMaster(cfg); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("policy key-wrap master: %w", err)
	} else if len(master) > 0 {
		w, err := policy.NewAESGCMWrapper(master)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("policy key-wrap aes-gcm: %w", err)
		}
		keyOpts = append(keyOpts, policy.WithKeyWrapper(w))
		logger.Info("policy: AES-256-GCM at-rest wrap enabled for signing seeds")
	}
	policyKeySvc := policy.NewKeyService(policyKeyRepo, auditRepo, keyOpts...)
	var policySigner policy.Signer = policyKeySvc
	var fileSigner *policy.KeySigner
	if cfg.Policy.SigningKeyPath != "" {
		ks, err := policy.LoadKeySignerFromFile(cfg.Policy.SigningKeyPath)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("policy signing key: %w", err)
		}
		policySigner = ks
		fileSigner = ks
		logger.Info("policy: using file-backed signing key (DB rotation endpoints remain available but will not take effect until POLICY_SIGNING_KEY_PATH is unset; /public-key endpoint serves this key uniformly for all tenants)",
			slog.String("path", cfg.Policy.SigningKeyPath),
			slog.String("key_id", ks.KeyID()))
	}
	appSvc := appdb.New(appRepo, appOverrideRepo, auditRepo, logger)
	appSyncer := appdb.NewSyncer(appSvc, nil)
	appRegHandler := handler.NewAppRegistryHandler(appSvc, nil, appSyncer)
	policySvc := policy.New(
		policyRepo,
		auditRepo,
		policySigner,
		policy.WithLogger(logger),
		policy.WithSteeringCompiler(appdb.PolicySteeringAdapter{Svc: appSvc}),
	)

	// When the file-backed signer is active, expose its public key
	// through the existing /signing-keys/{kid}/public-key endpoint
	// so receivers can resolve bundle `kid`s through the same
	// protocol surface used for DB-backed bundles. The DB-backed
	// rotation history remains accessible by its own kids.
	policyHandlerOpts := []handler.PolicyHandlerOption{}
	if fileSigner != nil {
		policyHandlerOpts = append(policyHandlerOpts, handler.WithFileBackedSigner(fileSigner))
	}
	webhookSvc := webhook.New(webhookEndpointRepo, webhookDeliveryRepo, auditRepo, logger)

	// Translate the operator-facing config.Webhook knobs into the
	// worker's internal WorkerConfig. The previous wiring passed
	// an empty WorkerConfig{}, which silently fell back to the
	// worker package's compiled-in defaults — meaning the
	// WEBHOOK_* environment variables were validated at boot but
	// never reached the live worker. Names differ across the two
	// layers because the config struct is the public API
	// (deliberately stable across worker refactors) while the
	// worker fields evolved with the implementation.
	webhookWorker := webhook.NewDeliveryWorker(
		webhookDeliveryRepo, webhookEndpointRepo, nil,
		webhook.WorkerConfig{
			BatchSize:         cfg.Webhook.BatchSize,
			PollInterval:      cfg.Webhook.PollInterval,
			RequestTimeout:    cfg.Webhook.DeliveryTimeout,
			MaxAttempts:       cfg.Webhook.MaxAttempts,
			BackoffBase:       cfg.Webhook.InitialDelay,
			BackoffMax:        cfg.Webhook.MaxDelay,
			ProcessingTimeout: cfg.Webhook.ProcessingTimeout,
			// WEBHOOK_SIGNATURE_HEADER is loaded + validated at
			// boot but used to be silently dropped here, so a
			// subscriber configured to look for a non-default
			// header (e.g. `X-Acme-Webhook-Sig`) saw every
			// signature as missing. Threading the value into
			// WorkerConfig restores the operator-facing contract.
			SignatureHeader: cfg.Webhook.SignatureHeader,
		},
		logger,
	)

	router := handler.NewRouter(handler.RouterDeps{
		Config:       cfg,
		Logger:       logger,
		Tenants:      handler.NewTenantHandler(tenantSvc),
		Sites:        handler.NewSiteHandler(siteSvc),
		Devices:      handler.NewDeviceHandler(identitySvc, deviceRepo, cfg.Auth.ClaimTokenTTL),
		RBAC:         handler.NewRBACHandler(rbacSvc),
		Policy:       handler.NewPolicyHandler(policySvc, policyKeySvc, policyHandlerOpts...),
		Audit:        handler.NewAuditHandler(auditSvc),
		Webhooks:     handler.NewWebhookHandler(webhookSvc),
		APIKeys:      handler.NewAPIKeyHandler(apiKeySvc),
		Telemetry:    handler.NewTelemetryHandler(replay),
		AppRegistry:  appRegHandler,
		APIKeyLookup: apiKeySvc,
		Health:       health,
		OpenAPISpec:  handler.NewOpenAPIHandler(),
	})
	// Return the AppRegistry handler so the caller can attach the
	// telemetry stats querier post-construction — the ClickHouse
	// writer is built later by startTelemetry and we want the
	// /app-registry/stats endpoint to come alive once the writer
	// is ready, without round-tripping through a setter on the
	// router.
	//
	// The Syncer is returned so main() can run its periodic
	// background loop alongside the HTTP server. Without that, the
	// admin `POST /admin/app-registry/sync` endpoint is the only
	// way to refresh vendor endpoints — which contradicts
	// docs/TRAFFIC_CLASSIFICATION.md's "24h cadence" contract.
	return router, webhookWorker, appRegHandler, appSyncer, nil
}

// loadPolicyKeyWrapMaster resolves the AES-GCM master key from
// config. Returns (nil, nil) when neither knob is set, so callers
// can detect "no wrap configured" without checking for a sentinel.
//
// We accept the master via env-style (base64 in
// POLICY_KEY_WRAP_MASTER_B64) and file-based (POLICY_KEY_WRAP_MASTER_FILE)
// to support both Kubernetes Secret mounts (file) and HashiCorp
// Vault / 12-factor (env) deployments.
func loadPolicyKeyWrapMaster(cfg *config.Config) ([]byte, error) {
	if cfg.Policy.KeyWrapMasterB64 != "" {
		// Reuse the policy package's decoder so the accept-list of
		// base64 dialects (std, raw, url, raw-url) stays in one
		// place.
		return policy.DecodeAESGCMMasterB64(cfg.Policy.KeyWrapMasterB64)
	}
	if cfg.Policy.KeyWrapMasterFile != "" {
		return policy.LoadAESGCMMasterFromFile(cfg.Policy.KeyWrapMasterFile)
	}
	return nil, nil
}

// startTelemetry builds the hot-path + cold-path writers and the
// consumer service, starts the consumer, and returns a shutdown
// closure that drains the writers + stops the consumer.
//
// Three operational shapes are supported:
//
//  1. Both ClickHouse and S3 configured \u2014 full production wiring.
//     Both writers buffer + flush asynchronously; a Write returning
//     nil means "queued, durable on next flush".
//  2. Only ClickHouse configured \u2014 cold archive disabled, no S3
//     keys land. Useful for cost-sensitive deployments that retain
//     full fidelity in ClickHouse and don't need long-term archive.
//  3. Neither configured \u2014 NoopHotWriter / NoopColdWriter take
//     over. The JetStream consumer still runs, dedup ring still
//     fires, DLQ machinery still routes broken payloads. This is
//     the local-dev default; the telemetry service's metrics
//     surface still works for debugging.
//
// The S3 writer accepts AWS-style credentials via standard env
// vars when S3_TELEMETRY_ACCESS_KEY_ID / SECRET are blank, so
// EC2 / EKS / Fargate IAM-role auth works without explicit
// configuration.
func startTelemetry(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	js jetstream.JetStream,
	pub *sngnats.Publisher,
) (func(context.Context) error, *chwriter.Writer, error) {
	var hot telemetry.HotWriter
	var cold telemetry.ColdWriter
	var hotStop func(context.Context) error
	var coldStop func(context.Context) error
	var chWriter *chwriter.Writer

	if len(cfg.TelemetryAnalytics.ClickHouseEndpoints) > 0 {
		chCfg := chwriter.Config{
			Endpoints:     cfg.TelemetryAnalytics.ClickHouseEndpoints,
			Database:      cfg.TelemetryAnalytics.ClickHouseDatabase,
			Table:         cfg.TelemetryAnalytics.ClickHouseTable,
			Username:      cfg.TelemetryAnalytics.ClickHouseUsername,
			Password:      cfg.TelemetryAnalytics.ClickHousePassword,
			TLS:           cfg.TelemetryAnalytics.ClickHouseTLS,
			FlushInterval: cfg.TelemetryAnalytics.ClickHouseFlushInterval,
			BatchSize:     cfg.TelemetryAnalytics.ClickHouseBatchSize,
		}
		w, err := chwriter.New(ctx, chCfg, logger)
		if err != nil {
			return nil, nil, fmt.Errorf("clickhouse writer: %w", err)
		}
		if cfg.TelemetryAnalytics.ClickHouseEnsureSchema {
			if err := w.EnsureSchema(ctx); err != nil {
				_ = w.Stop(ctx)
				return nil, nil, fmt.Errorf("clickhouse schema: %w", err)
			}
		}
		hot = w
		hotStop = w.Stop
		chWriter = w
		logger.Info("telemetry: clickhouse hot-path writer enabled",
			slog.String("endpoints", strings.Join(chCfg.Endpoints, ",")),
			slog.String("database", chCfg.Database),
			slog.String("table", chCfg.Table))
	}

	if cfg.TelemetryAnalytics.S3Bucket != "" {
		awsCfg, err := loadAWSConfig(ctx, cfg)
		if err != nil {
			if hotStop != nil {
				_ = hotStop(ctx)
			}
			return nil, nil, fmt.Errorf("aws config: %w", err)
		}
		s3Cfg := s3writer.Config{
			Bucket:             cfg.TelemetryAnalytics.S3Bucket,
			Prefix:             cfg.TelemetryAnalytics.S3Prefix,
			StorageClass:       cfg.TelemetryAnalytics.S3StorageClass,
			FlushInterval:      cfg.TelemetryAnalytics.S3FlushInterval,
			MaxBytesPerObject:  cfg.TelemetryAnalytics.S3MaxBytesPerObject,
			MaxEventsPerObject: cfg.TelemetryAnalytics.S3MaxEventsPerObject,
		}
		w, err := s3writer.NewWithAWSConfig(awsCfg, s3Cfg, logger)
		if err != nil {
			if hotStop != nil {
				_ = hotStop(ctx)
			}
			return nil, nil, fmt.Errorf("s3 writer: %w", err)
		}
		cold = w
		coldStop = w.Stop
		logger.Info("telemetry: s3 cold-path archive enabled",
			slog.String("bucket", s3Cfg.Bucket),
			slog.String("prefix", s3Cfg.Prefix))
	}

	svc, err := telemetry.New(js, &cfg.NATS, telemetry.Config{}, hot, cold, logger)
	if err != nil {
		if hotStop != nil {
			_ = hotStop(ctx)
		}
		if coldStop != nil {
			_ = coldStop(ctx)
		}
		return nil, nil, fmt.Errorf("telemetry service: %w", err)
	}
	svc.WithDLQ(pub)
	if err := svc.Start(ctx); err != nil {
		if hotStop != nil {
			_ = hotStop(ctx)
		}
		if coldStop != nil {
			_ = coldStop(ctx)
		}
		return nil, nil, fmt.Errorf("telemetry start: %w", err)
	}
	logger.Info("telemetry: consumer started")

	shutdown := func(sCtx context.Context) error {
		var firstErr error
		if err := svc.Stop(sCtx); err != nil && firstErr == nil {
			firstErr = err
		}
		if hotStop != nil {
			if err := hotStop(sCtx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if coldStop != nil {
			if err := coldStop(sCtx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return shutdown, chWriter, nil
}

// clickhouseStatsAdapter bridges chwriter.Writer (which returns
// []chwriter.TrafficClassCount) to handler.TelemetryClassQuerier
// (which expects []handler.TrafficClassStat). The two payload
// types are structurally identical but live in separate packages
// so the handler does not import the clickhouse subpackage. The
// adapter is the seam that keeps that boundary clean.
type clickhouseStatsAdapter struct {
	w *chwriter.Writer
}

func (a clickhouseStatsAdapter) QueryTrafficClassDistribution(
	ctx context.Context,
	tenantID uuid.UUID,
	since time.Time,
) ([]handler.TrafficClassStat, error) {
	rows, err := a.w.QueryTrafficClassDistribution(ctx, tenantID, since)
	if err != nil {
		return nil, err
	}
	out := make([]handler.TrafficClassStat, len(rows))
	for i, r := range rows {
		out[i] = handler.TrafficClassStat{
			Class:  r.Class,
			Events: r.Events,
			Bytes:  r.Bytes,
		}
	}
	return out, nil
}

// loadAWSConfig resolves an AWS config for the cold-path writer.
// Honours an explicit access-key / secret pair from config when
// supplied (for MinIO / R2 style deployments where IAM roles
// aren't available); otherwise defers to the SDK's default
// credentials chain (env vars, shared profile, EC2/IMDS, ECS
// task role, EKS IRSA, etc.).
func loadAWSConfig(ctx context.Context, cfg *config.Config) (aws.Config, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if cfg.TelemetryAnalytics.S3Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.TelemetryAnalytics.S3Region))
	}
	if cfg.TelemetryAnalytics.S3AccessKeyID != "" && cfg.TelemetryAnalytics.S3SecretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.TelemetryAnalytics.S3AccessKeyID,
				cfg.TelemetryAnalytics.S3SecretAccessKey,
				"",
			),
		))
	}
	if cfg.TelemetryAnalytics.S3Endpoint != "" {
		loadOpts = append(loadOpts, awsconfig.WithBaseEndpoint(cfg.TelemetryAnalytics.S3Endpoint))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, err
	}
	return awsCfg, nil
}

// newLogger constructs the process-wide structured logger.
func newLogger(cfg *config.Config) *slog.Logger {
	level := parseLogLevel(cfg.Log.Level)
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Log.Format)) {
	case "text", "console":
		h = slog.NewTextHandler(os.Stderr, opts)
	default:
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h).With(
		slog.String("app", cfg.AppName),
		slog.String("env", string(cfg.Environment)),
	)
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// openPostgres opens a pgx connection pool using the configured DSN
// and pings it to verify connectivity at startup. Returning before
// the pool is reachable lets operators see a clear boot-time error
// instead of a flapping readiness probe.
func openPostgres(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.Postgres.DSN())
	if err != nil {
		return nil, fmt.Errorf("parse postgres DSN: %w", err)
	}
	// pgxpool has no `MaxIdleConns` ceiling (excess idle connections
	// are retired by MaxConnIdleTime); the closest knob is MinConns
	// which is a *floor* the pool eagerly maintains. Wire our
	// MinConns config field straight through — the field name and
	// the env var (PG_MIN_CONNS) match the pgx semantic so the
	// operator's intent and the pool's behaviour can't drift.
	poolCfg.MaxConns = int32(cfg.Postgres.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.Postgres.MinConns)
	poolCfg.MaxConnLifetime = cfg.Postgres.ConnMaxLifetime
	poolCfg.ConnConfig.ConnectTimeout = cfg.Postgres.ConnTimeout

	// If PG_APP_ROLE is set, every new physical connection
	// adopts that role for its session lifetime via `SET SESSION
	// ROLE`. This is the runtime half of the role-separation
	// architecture documented in `docs/deploy.md`: the pool
	// authenticates as a LOGIN user (typically `sng_app_login`,
	// NOINHERIT, member of `sng_app`) and immediately demotes to
	// the NOLOGIN runtime role so RLS policies — which Postgres
	// bypasses for superusers and OWNER of the table — apply to
	// every query the application issues.
	//
	// The AfterConnect hook then verifies `current_user` matches
	// the requested role. This catches three classes of
	// silent-misconfiguration bugs that would otherwise bypass
	// the security model:
	//   1. Operator points PG_USER at a superuser, so `SET
	//      SESSION ROLE` silently no-ops (the superuser ALREADY
	//      has every privilege; the demotion still happens but
	//      RLS would be bypassed by `BYPASSRLS` if granted).
	//   2. The login user is missing membership in the runtime
	//      role; `SET SESSION ROLE` would error and pgx rejects
	//      the connection (this case is already loud — listed
	//      for completeness).
	//   3. The pooler runs in transaction-pooling mode and the
	//      `SET SESSION ROLE` is reverted between transactions;
	//      this would manifest as alternating successful and
	//      `permission denied` queries, but the boot-time probe
	//      below at least verifies the first connection is
	//      configured correctly.
	if cfg.Postgres.AppRole != "" {
		poolCfg.AfterConnect = afterConnectSetRole(cfg.Postgres.AppRole)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, cfg.Postgres.ConnTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	logger.Info("sng-control: postgres connected",
		slog.String("host", cfg.Postgres.Host),
		slog.Int("port", cfg.Postgres.Port),
		slog.String("database", cfg.Postgres.Database),
		slog.String("app_role", cfg.Postgres.AppRole))
	return pool, nil
}

// afterConnectSetRole returns a pgxpool.AfterConnect hook that
// adopts `appRole` on every new physical connection and verifies
// the demotion took effect. See the call site in openPostgres for
// the full rationale.
//
// Exposed as a package-level function (rather than an inline
// closure) so unit tests can exercise the SQLSTATE-handling paths
// against a mock connection without going through the full
// pgxpool.NewWithConfig boot sequence.
func afterConnectSetRole(appRole string) func(context.Context, *pgx.Conn) error {
	roleIdent := pgx.Identifier{appRole}.Sanitize()
	setRoleSQL := fmt.Sprintf("SET SESSION ROLE %s", roleIdent)
	return func(ctx context.Context, conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, setRoleSQL); err != nil {
			return fmt.Errorf("set session role %q: %w", appRole, err)
		}
		var current string
		if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&current); err != nil {
			return fmt.Errorf("verify current_user after SET SESSION ROLE: %w", err)
		}
		if current != appRole {
			return fmt.Errorf(
				"post-SET SESSION ROLE current_user = %q, want %q (check PG_APP_ROLE / login-user membership)",
				current, appRole,
			)
		}
		return nil
	}
}

// openNATS connects to the NATS cluster and verifies JetStream is
// reachable. The control plane is not useful without JetStream, so
// a JetStream-disabled or unreachable cluster fails boot rather than
// degrading silently at first publish time.
func openNATS(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name(cfg.NATS.Name),
		nats.ReconnectWait(cfg.NATS.ReconnectWait),
		nats.MaxReconnects(cfg.NATS.MaxReconnects),
		// nats.Timeout sets the connect dial deadline, NOT a
		// per-request deadline. Wire the dedicated
		// NATS_CONNECT_TIMEOUT here so operators can tune dial
		// latency budgets independently from per-request deadlines
		// (NATS_REQUEST_TIMEOUT, consumed when we start issuing
		// JetStream RequestWithContext / PublishOpts in PR 4).
		nats.Timeout(cfg.NATS.ConnectTimeout),
	}
	if cfg.NATS.User != "" || cfg.NATS.Password != "" {
		opts = append(opts, nats.UserInfo(cfg.NATS.User, cfg.NATS.Password))
	}
	if cfg.NATS.Token != "" {
		opts = append(opts, nats.Token(cfg.NATS.Token))
	}
	if cfg.NATS.CredsFile != "" {
		opts = append(opts, nats.UserCredentials(cfg.NATS.CredsFile))
	}

	tlsOpts, err := buildNATSTLSOptions(&cfg.NATS)
	if err != nil {
		return nil, fmt.Errorf("build TLS: %w", err)
	}
	opts = append(opts, tlsOpts...)

	nc, err := nats.Connect(cfg.NATS.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream client: %w", err)
	}
	// nc.JetStream() above only constructs a *client-side* JetStream
	// context — it does NOT round-trip to the server, so a NATS cluster
	// without JetStream enabled would pass this check and only fail at
	// first publish/consumer-create. Force a real server round-trip by
	// calling AccountInfo. nats.go maps the "no responders" reply that
	// a JetStream-disabled server returns to ErrJetStreamNotEnabled, so
	// operators get a clear boot-time error rather than a flapping
	// readiness probe later. We budget the call against the dedicated
	// NATS_REQUEST_TIMEOUT so a hung server can't pin boot forever.
	jsCtx, cancel := context.WithTimeout(ctx, cfg.NATS.RequestTimeout)
	defer cancel()
	if _, err := js.AccountInfo(nats.Context(jsCtx)); err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream account info: %w", err)
	}
	logger.Info("sng-control: nats connected",
		slog.String("url", redactURL(cfg.NATS.URL)),
		slog.String("stream_prefix", cfg.NATS.StreamPrefix))
	return nc, nil
}

// buildNATSTLSOptions converts the TLS-related env-driven config into
// nats.Option values applied at connect time. It builds a single
// *tls.Config from the env config and threads it through
// nats.Secure(). This lets us:
//   - pin a tenant-supplied CA file (NATS_TLS_CA),
//   - present a client certificate for mTLS
//     (NATS_TLS_CERT + NATS_TLS_KEY),
//   - allow operators to opt into self-signed deployments during
//     local development (NATS_TLS_INSECURE) which is blocked in
//     production by config validation.
//
// All three fields are independent: a deployment can run server-auth
// only (CA but no client cert), or mTLS (cert+key) layered on top of
// a custom CA, or mTLS with the system pool. We do not require
// the URL scheme to be tls://: the nats.go client triggers TLS
// whenever the connect-time options carry a tls.Config, and a tls://
// URL still works because the TLS config layers on top.
//
// Both the CA file and the cert/key pair are read and parsed exactly
// once here, at boot, so any malformed file fails the process before
// the first connect attempt — and we avoid the TOCTOU window where
// nats.go would read the CA file a second time at handshake time.
func buildNATSTLSOptions(n *config.NATS) ([]nats.Option, error) {
	hasCert := n.TLSCertFile != "" && n.TLSKeyFile != ""
	hasCA := n.TLSCAFile != ""

	// Reject half-specified mTLS up front so that an operator who
	// set NATS_TLS_CERT but forgot NATS_TLS_KEY (or vice-versa) sees
	// a clear error instead of a silent fall-back to anonymous TLS.
	if (n.TLSCertFile != "") != (n.TLSKeyFile != "") {
		return nil, errors.New("NATS_TLS_CERT and NATS_TLS_KEY must both be set or both empty")
	}

	if !hasCA && !hasCert && !n.TLSInsecure {
		return nil, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if hasCA {
		pem, err := os.ReadFile(n.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read NATS_TLS_CA %q: %w", n.TLSCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("NATS_TLS_CA %q: no PEM certificates found", n.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	if hasCert {
		kp, err := tls.LoadX509KeyPair(n.TLSCertFile, n.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load NATS_TLS_CERT/NATS_TLS_KEY: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{kp}
	}

	if n.TLSInsecure {
		// Gated by config.validate(): production refuses true.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	return []nats.Option{nats.Secure(tlsCfg)}, nil
}

// redactURL strips userinfo from a NATS URL string so it is safe to
// emit in logs. Operators who embed `nats://user:password@host:4222`
// instead of using the dedicated NATS_USER/NATS_PASSWORD fields
// should still not leak their secret through info-level boot logs.
//
// NATS_URL legitimately accepts a *comma-separated* list of server
// URLs (e.g. `nats://u:p@h1:4222,nats://u:p@h2:4222`) which is the
// idiomatic way to spell a NATS cluster. url.Parse on the joined
// string would see a single garbled host and could leak credentials
// from every entry after the first, so we split the list, redact
// each segment independently with redactSingleURL, and rejoin.
func redactURL(raw string) string {
	if raw == "" {
		return raw
	}
	if !strings.Contains(raw, ",") {
		return redactSingleURL(raw)
	}
	parts := strings.Split(raw, ",")
	for i, p := range parts {
		trim := strings.TrimSpace(p)
		red := redactSingleURL(trim)
		// Preserve any whitespace padding around the original
		// entry — a copy-paste from a YAML list often carries a
		// leading space and we don't want the redacted log to look
		// gratuitously different from what the operator typed.
		if lead := leadingSpaces(p); lead != "" {
			red = lead + red
		}
		if trail := trailingSpaces(p); trail != "" {
			red += trail
		}
		parts[i] = red
	}
	return strings.Join(parts, ",")
}

// redactSingleURL is the single-URL redactor extracted from redactURL
// so the comma-separated branch can reuse it per-segment.
func redactSingleURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err == nil && u.User != nil {
		return u.Redacted()
	}
	if err != nil {
		if i := strings.LastIndex(raw, "@"); i > 0 {
			if j := strings.Index(raw, "://"); j >= 0 && i > j {
				return raw[:j+3] + "REDACTED@" + raw[i+1:]
			}
		}
	}
	return raw
}

func leadingSpaces(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			return s[:i]
		}
	}
	return s
}

func trailingSpaces(s string) string {
	for i := len(s); i > 0; i-- {
		c := s[i-1]
		if c != ' ' && c != '\t' {
			return s[i:]
		}
	}
	return s
}
