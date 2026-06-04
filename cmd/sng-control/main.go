// Command sng-control is the ShieldNet Gateway control-plane service
// entrypoint. It loads configuration from the environment, opens
// connections to NATS and PostgreSQL, and serves the operator HTTP
// API alongside health and readiness probes.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/metrics"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	sngotel "github.com/kennguy3n/visible-fishbone/internal/otel"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	aisvc "github.com/kennguy3n/visible-fishbone/internal/service/ai"
	"github.com/kennguy3n/visible-fishbone/internal/service/alert"
	"github.com/kennguy3n/visible-fishbone/internal/service/apikey"
	"github.com/kennguy3n/visible-fishbone/internal/service/appdb"
	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
	casbconnectors "github.com/kennguy3n/visible-fishbone/internal/service/casb/connectors"
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration/connectors"
	"github.com/kennguy3n/visible-fishbone/internal/service/leader"
	"github.com/kennguy3n/visible-fishbone/internal/service/metering"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook/executors"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
	"github.com/kennguy3n/visible-fishbone/internal/service/pop"
	"github.com/kennguy3n/visible-fishbone/internal/service/rbac"
	"github.com/kennguy3n/visible-fishbone/internal/service/site"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
	chwriter "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/clickhouse"
	telreplay "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/replay"
	s3writer "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/s3"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
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

	// Distributed tracing. Always installs the W3C TraceContext +
	// Baggage propagator; only stands up a real OTLP exporter when
	// OTEL_EXPORTER_OTLP_ENDPOINT is configured (otherwise the
	// global tracer stays the no-op and tracerShutdown is a no-op).
	tracerShutdown, err := sngotel.InitTracer(rootCtx, cfg.Telemetry, cfg.AppName, string(cfg.Environment))
	if err != nil {
		return fmt.Errorf("init tracer: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracerShutdown(shutCtx); err != nil {
			logger.Warn("sng-control: tracer shutdown error", slog.Any("error", err))
		}
	}()
	if cfg.Telemetry.OTLPEndpoint != "" {
		logger.Info("sng-control: otel tracing enabled",
			slog.String("endpoint", cfg.Telemetry.OTLPEndpoint))
	}

	// Prometheus metrics registry. Constructed once and threaded
	// into the router (HTTP instrumentation middleware) and the
	// background pool / JetStream collectors. Nil when disabled, in
	// which case every consumer degrades to a no-op.
	var mx *metrics.Metrics
	if cfg.Metrics.Enabled {
		mx = metrics.New(cfg.Metrics)
	}

	pool, err := openPostgres(rootCtx, &cfg, logger)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()
	// Begin evicting unhealthy read replicas from the rotation. No-op
	// when no replicas are configured. Bound to rootCtx so the loop
	// winds down with the rest of the process.
	pool.StartHealthChecks(rootCtx)

	// Leader election for singleton workloads. Every replica runs
	// the elector and the HTTP server + NATS consumers; only the
	// replica that holds the Postgres advisory lock runs the
	// singleton background loops (wrapped in RunIfLeader below). The
	// lock is taken on the PRIMARY pool — never a read replica. To
	// scale the control plane horizontally, deploy 2–3 replicas
	// behind a load balancer: all serve API traffic and consume
	// telemetry, and exactly one runs the singletons; on leader
	// crash the advisory lock is released by Postgres when the dead
	// session is reaped and another replica takes over within one
	// election interval.
	identity, _ := os.Hostname()
	elector := leader.New(
		leader.NewPgSessionOpener(pool.Primary()),
		leader.WithIdentity(identity),
		leader.WithLogger(logger),
	)
	// The elector holds a dedicated primary-pool connection for the
	// advisory lock's lifetime. Run it under its own cancellable
	// context and block shutdown on its relinquish so the deferred
	// pool.Close() (registered earlier, hence run later — defers are
	// LIFO) never races the elector still returning its connection.
	// The wait is bounded so a wedged relinquish (e.g. primary
	// partition) cannot hang graceful shutdown indefinitely.
	electorCtx, electorCancel := context.WithCancel(rootCtx)
	electorDone := make(chan struct{})
	go func() {
		defer close(electorDone)
		elector.Run(electorCtx)
	}()
	defer func() {
		electorCancel()
		select {
		case <-electorDone:
		case <-time.After(5 * time.Second):
			logger.Warn("sng-control: timed out waiting for leader elector to relinquish")
		}
	}()

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
		return pool.Primary().Ping(ctx)
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

	router, webhookWorker, integrationWorker, appRegHandler, appSyncer, policySimHandler, aiSvc, meteringSvc, popSvc, evidenceScheduler, err := buildRouter(&cfg, logger, pool, health, telReplay, telPublisher, mx)
	if err != nil {
		return fmt.Errorf("build router: %w", err)
	}

	// Start the cost-metering flush loop. It batch-upserts the
	// accumulated per-tenant usage deltas into tenant_usage every
	// FlushInterval and performs a final flush when rootCtx is
	// cancelled, so usage recorded just before shutdown is not lost.
	// Block shutdown on its completion (bounded) so the deferred
	// pool.Close() (registered earlier, hence run later — defers are
	// LIFO) never races the final flush still writing on a connection
	// from the pool, which would drop the trailing usage window. The
	// wait exceeds Run's own 10s final-flush timeout so a healthy
	// flush always lands; a wedged flush cannot hang shutdown forever.
	meteringDone := make(chan struct{})
	go func() {
		defer close(meteringDone)
		meteringSvc.Run(rootCtx)
	}()
	defer func() {
		select {
		case <-meteringDone:
		case <-time.After(15 * time.Second):
			logger.Warn("sng-control: timed out waiting for metering final flush")
		}
	}()

	// Start the webhook delivery worker before the HTTP server so
	// queued deliveries from a previous run start draining
	// immediately on boot. Stopped during shutdown below.
	if err := webhookWorker.Start(rootCtx); err != nil {
		return fmt.Errorf("start webhook worker: %w", err)
	}
	// Same boot ordering as the webhook worker — pending
	// IntegrationDelivery rows queued by a previous process
	// resume dispatch before the HTTP server starts accepting
	// new traffic.
	if err := integrationWorker.Start(rootCtx); err != nil {
		return fmt.Errorf("start integration worker: %w", err)
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
		// Singleton: only the leader runs the periodic sync, so a
		// multi-replica deployment performs exactly one vendor fetch
		// per interval instead of one per replica. RunIfLeader
		// blocks until rootCtx is cancelled and starts/stops the
		// loop as leadership is gained/lost, so it is launched in
		// its own goroutine.
		go elector.RunIfLeader(rootCtx, "app-registry-sync", func(ctx context.Context) {
			appSyncer.Run(ctx, cfg.AppRegistry.SyncInterval)
		})
		logger.Info("sng-control: app-registry sync loop registered (runs on leader only)",
			slog.Duration("interval", cfg.AppRegistry.SyncInterval))
	} else {
		logger.Info("sng-control: app-registry sync loop disabled (APP_REGISTRY_SYNC_ENABLED=false)")
	}

	// --- Cloud PoP service (Session F) -------------------------------
	// Every replica keeps its own lock-free PoP registry warm by
	// refreshing it from Postgres on PoP.RegistryRefreshInterval, so a
	// load-balanced AssignPoP / public-bootstrap request hits a local
	// snapshot rather than the DB. Health beacons published by PoP
	// edges on `sng.pop.<id>.health` (core NATS — high-frequency,
	// ephemeral telemetry that must not be persisted in JetStream) are
	// folded into the same registry in real time so a PoP that goes
	// hot or silent drops out of the assignable set within one TTL
	// window instead of one refresh interval.
	// Warm the registry from Postgres synchronously BEFORE subscribing
	// to health beacons. ApplyHealth drops beacons for PoPs the registry
	// has not loaded yet, so subscribing first would open a startup
	// window where early beacons are dropped from the in-memory snapshot
	// (they are still persisted and self-heal on the next refresh, but
	// warming first closes the window). Run still owns the periodic
	// refresh loop below.
	if err := popSvc.Registry().Refresh(rootCtx); err != nil {
		logger.Warn("sng-control: initial pop registry refresh failed", slog.Any("error", err))
	}
	popHealthSub, err := subscribePoPHealth(nc, popSvc, logger)
	if err != nil {
		return fmt.Errorf("subscribe pop health: %w", err)
	}
	defer func() {
		// Drain (not just unsubscribe) so in-flight beacons finish
		// being folded into the registry before shutdown.
		if err := popHealthSub.Drain(); err != nil {
			logger.Warn("sng-control: pop health subscription drain failed", slog.Any("error", err))
		}
	}()
	go popSvc.Run(rootCtx, cfg.PoP.RegistryRefreshInterval)
	// The capacity rebalancer is a singleton: only the leader scans
	// for overloaded PoPs and moves non-override tenants off them, so
	// a multi-replica deployment performs one coordinated rebalance
	// per interval rather than N racing ones (which would thrash
	// assignments). Disabled via POP_REBALANCE_ENABLED=false.
	if cfg.PoP.RebalanceEnabled {
		go elector.RunIfLeader(rootCtx, "pop-rebalance", func(ctx context.Context) {
			runPoPRebalance(ctx, popSvc, cfg.PoP.RebalanceInterval, logger)
		})
		logger.Info("sng-control: pop rebalance loop registered (runs on leader only)",
			slog.Duration("interval", cfg.PoP.RebalanceInterval))
	} else {
		logger.Info("sng-control: pop rebalance loop disabled (POP_REBALANCE_ENABLED=false)")
	}

	// SOC2 evidence collection is a singleton background workload:
	// only the leader runs the weekly collection / monthly aggregation
	// / gap-detection loop, so a multi-replica deployment produces one
	// signed bundle per cadence rather than one per replica.
	// RunIfLeader blocks until rootCtx is cancelled, so it runs in its
	// own goroutine.
	if evidenceScheduler != nil {
		go elector.RunIfLeader(rootCtx, "compliance-evidence", evidenceScheduler.Run)
		logger.Info("sng-control: compliance evidence scheduler registered (runs on leader only)")
	}

	rawTelShutdown, chStats, chReaderFactory, err := startTelemetry(rootCtx, &cfg, logger, js, telPublisher)
	if err != nil {
		return fmt.Errorf("start telemetry: %w", err)
	}
	// Wire the ClickHouse hot tier into the AppRegistry handler so
	// the /app-registry/stats endpoint can serve per-class
	// distributions. When ClickHouse is not configured, chStats is
	// nil and the handler keeps returning 503 on /stats. chStats is
	// satisfied by either the single-cluster *Writer or the
	// shard-aware *ShardedWriter, so this path is identical in both
	// modes.
	if chStats != nil {
		appRegHandler.SetStats(chStats)

		// Wire the policy simulator now that the ClickHouse hot
		// tier is alive. The reader factory shares the writer's
		// connection(s), so we don't open a second pool just for
		// reads — and the simulator's lifecycle is bound to the
		// telemetry stack's, which is exactly what we want
		// (operator-driven simulation requires recent telemetry).
		if policySimHandler != nil {
			chReader, rErr := chReaderFactory()
			if rErr != nil {
				logger.Warn("policy.simulator: clickhouse reader unavailable; /simulations endpoint returns 503",
					slog.String("error", rErr.Error()))
			} else {
				sim, sErr := policy.NewSimulator(chReader, policy.GraphEvaluatorFactory{}, policy.WithSimulatorLogger(logger))
				if sErr != nil {
					logger.Warn("policy.simulator: construction failed; /simulations endpoint returns 503",
						slog.String("error", sErr.Error()))
				} else {
					policySimHandler.SetSimulator(sim)
					logger.Info("policy.simulator: wired to clickhouse hot tier")
				}
			}
		}
	}

	// Wire the AI summarizer. Template mode works without
	// ClickHouse; when an EvidenceReader adapter for the CH hot
	// tier is built, pass it instead of nil to enable
	// evidence-grounded summaries.
	if aiSvc != nil {
		aiSvc.SetSummarizer(aisvc.NewSummarizer(aiSvc.LLM(), nil))
		logger.Info("ai.summarizer: wired (template-mode; evidence reader pending)")
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

	// Internal metrics surface. Bound to a dedicated port
	// (METRICS_PORT, default 9090) — never the public API
	// listener — so the `/metrics` exposition (tenant counts, pool
	// sizes, NATS lag) stays on the cluster-internal network. The
	// background pool / JetStream collectors feed gauges that the
	// scrape then reads. config.validate already guaranteed the
	// port differs from HTTP.Port.
	var metricsSrv *http.Server
	if mx != nil {
		// Pool gauges track the primary (writer) pool; it carries
		// the acquire/idle pressure the collector reports. pool is a
		// *postgres.ReadWritePool wrapper, so reach the underlying
		// *pgxpool.Pool (which exposes Stat) via Primary().
		go metrics.NewPGCollector(mx, pool.Primary(), metrics.DefaultPoolScrapeInterval).Run(rootCtx)
		streamNames := make([]string, 0, len(streams))
		for _, s := range streams {
			streamNames = append(streamNames, s.Name)
		}
		go metrics.NewNATSCollector(mx, js, streamNames, metrics.DefaultConsumerScrapeInterval, logger).Run(rootCtx)

		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", mx.Handler())
		metricsSrv = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Metrics.Port),
			Handler: metricsMux,
			// Mirror the public API server's full timeout set so a
			// slow or stuck scraper cannot hold a metrics connection
			// open indefinitely. Scrapes are small, so the same
			// bounds are comfortably generous here.
			ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
		}
		go func() {
			logger.Info("sng-control: metrics server listening",
				slog.Int("port", cfg.Metrics.Port),
				slog.String("namespace", cfg.Metrics.Namespace))
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				// A metrics-listener failure must not take down the
				// control plane; log loudly and carry on serving the
				// API.
				logger.Error("sng-control: metrics server error", slog.Any("error", err))
			}
		}()
	}

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
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("sng-control: metrics shutdown error", slog.Any("error", err))
		}
	}

	if err := webhookWorker.Stop(shutdownCtx); err != nil {
		logger.Warn("sng-control: webhook worker shutdown error", slog.Any("error", err))
	}
	if err := integrationWorker.Stop(shutdownCtx); err != nil {
		logger.Warn("sng-control: integration worker shutdown error", slog.Any("error", err))
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
	pool *postgres.ReadWritePool,
	health *handler.Health,
	replay *telreplay.Worker,
	telPub *sngnats.Publisher,
	mx *metrics.Metrics,
) (http.Handler, *webhook.DeliveryWorker, *integration.DeliveryWorker, *handler.AppRegistryHandler, *appdb.Syncer, *handler.PolicySimulationHandler, *aisvc.Service, *metering.MeteringService, *pop.Service, *compliance.Scheduler, error) {
	store := postgres.NewStoreWithPool(pool)

	tenantRepo := store.NewTenantRepository()
	siteRepo := store.NewSiteRepository()
	// Short-TTL cache for the auth-middleware mobile device kill-switch.
	// Decorating the device repository here means every status mutation
	// (suspend / delete / reactivate) — through any service — invalidates
	// the matching entry, so the kill-switch stays immediate while the
	// per-request GetByPublicKey lookups collapse to one per TTL window.
	mobileDeviceStatusCache := handler.NewMobileDeviceStatusCache(handler.DefaultMobileDeviceStatusTTL)
	deviceRepo := mobileDeviceStatusCache.InstrumentRepository(store.NewDeviceRepository())
	roleRepo := store.NewRoleRepository()
	claimRepo := store.NewClaimTokenRepository()
	auditRepo := store.NewAuditLogRepository()
	policyRepo := store.NewPolicyRepository()
	policyKeyRepo := store.NewPolicySigningKeyRepository()
	policyRolloutRepo := store.NewPolicyRolloutRepository()
	webhookEndpointRepo := store.NewWebhookEndpointRepository()
	webhookDeliveryRepo := store.NewWebhookDeliveryRepository()
	apiKeyRepo := store.NewTenantAPIKeyRepository()
	appRepo := store.NewAppRegistryRepository()
	appOverrideRepo := store.NewAppRegistryOverrideRepository()
	baselineRepo := store.NewBaselineModelRepository()
	alertRepo := store.NewAlertRepository()
	alertSuppressionRepo := store.NewAlertSuppressionRepository()
	alertFeedbackRepo := store.NewAlertFeedbackRepository()
	integrationConnectorRepo := store.NewIntegrationConnectorRepository()
	integrationDeliveryRepo := store.NewIntegrationDeliveryRepository()
	mspRepo := store.NewMSPRepository()
	enrollmentRepo := store.NewDeviceEnrollmentRepository()
	casbConnectorRepo := store.NewCASBConnectorRepository()
	casbAppRepo := store.NewCASBDiscoveredAppRepository()
	casbPostureRepo := store.NewCASBPostureCheckRepository()
	opsHealthRepo := store.NewOpsHealthSnapshotRepository()
	aiSuggestionRepo := store.NewAISuggestionRepository()

	tenantSvc := tenant.New(tenantRepo, auditRepo, logger)
	siteSvc := site.New(siteRepo, auditRepo, logger)
	identitySvc := identity.New(deviceRepo, claimRepo, auditRepo, logger)
	enrollmentSvc := identity.NewEnrollmentService(enrollmentRepo, claimRepo, auditRepo, logger)
	userRepo := store.NewUserRepository()
	scimSvc := identity.NewSCIMService(userRepo, roleRepo, auditRepo)
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
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("policy key-wrap master: %w", err)
	} else if len(master) > 0 {
		w, err := policy.NewAESGCMWrapper(master)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("policy key-wrap aes-gcm: %w", err)
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
			return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("policy signing key: %w", err)
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

	// PolicySimulationHandler is constructed only when both
	// the rollout repo and a CanaryService can be built. The
	// Simulator itself is wired without a TelemetrySource for
	// now (deployments without a ClickHouse hot tier can still
	// drive rollouts manually) — operator-triggered simulation
	// returns 503 until ClickHouse is wired via a future
	// startup pass. The rollout / dry-run / advance paths
	// don't depend on the simulator and remain fully
	// functional.
	// NewCanaryService currently only fails when either of its
	// required deps is nil — which would be a programmer error
	// at startup, not a runtime condition. Surface it as a
	// fatal log so we never silently start a control plane with
	// a missing rollout state machine (per PR #39 Devin Review
	// ANALYSIS_0002): a future option (e.g. a clock injection
	// guard, or a CanaryConfig validator) could introduce real
	// failures, and silently dropping that error would leave
	// the simulation handler wired to a nil service.
	canarySvc, err := policy.NewCanaryService(policySvc, policyRolloutRepo,
		policy.WithCanaryLogger(logger))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("control: build canary service: %w", err)
	}
	policySimHandler := handler.NewPolicySimulationHandler(
		policySvc, canarySvc, nil, policyRepo, logger)

	// Baseline + alert services (Phase 3 Block 3, Tasks 11-15).
	// The Router takes a Publisher for NATS lifecycle events on
	// `sng.<tenant>.alerts.*`; we adapt sngnats.Publisher's 4-arg
	// signature to the 3-arg slice the Router needs. Passing nil
	// is safe (Router checks for nil pub on every publish); in
	// practice the publisher is always wired here so the operator
	// portal can subscribe to fresh alerts in realtime.
	alertRouter := alert.NewRouter(
		alertRepo, alertSuppressionRepo,
		natsAlertAdapter{p: telPub},
		alert.Options{Logger: logger},
	)
	alertFeedback := alert.NewFeedback(
		alertFeedbackRepo, alertRepo, baselineRepo,
		alert.FeedbackTuningOptions{},
	)
	// Scope the tuning loop's logger so operators can filter
	// `component=alert-feedback` to triage missing threshold
	// adjustments without scrolling through every router log.
	alertFeedback.SetLogger(logger.With(slog.String("component", "alert-feedback")))
	// NOTE: baseline.NewService(baselineRepo) is intentionally
	// NOT constructed here. The Service / Detector pair is
	// wired by the telemetry consumer (future block) once the
	// dispatch path is ready to feed Observations in; until
	// then, alert.Feedback / alert.Router operate on the
	// baseline repo directly for threshold tuning and
	// suppression matching, which does not require the
	// score-then-fold service surface.

	// Integration service + worker (Phase 3 Block 4, Task 21).
	// Registry maps every IntegrationConnectorType to its plugin.
	// We construct each connector with a shared http.Client so
	// the deployment's outbound HTTPS budget is uniform across
	// SIEM / Jira / ServiceNow. Syslog is wired with nil dialer
	// so the connector falls back to net.Dial / tls.Dial as
	// appropriate per connector.Scheme. The worker is started
	// alongside the webhook worker (see Start/Stop sites below).
	integrationHTTP := &http.Client{Timeout: 15 * time.Second}
	integrationUA := cfg.AppName + "/sng-control"
	integrationRegistry := integration.Registry{
		repository.IntegrationConnectorSyslog:      connectors.NewSyslog(nil, 5*time.Second, hostnameForSyslog()),
		repository.IntegrationConnectorSIEMWebhook: connectors.NewSIEM(integrationHTTP, integrationUA),
		repository.IntegrationConnectorJira:        connectors.NewJira(integrationHTTP, integrationUA),
		repository.IntegrationConnectorServiceNow:  connectors.NewServiceNow(integrationHTTP, integrationUA),
	}
	integrationSvc := integration.New(
		integrationConnectorRepo, integrationDeliveryRepo, auditRepo,
		integrationRegistry, logger)
	// Translate the operator-facing cfg.Integration knobs into
	// the worker's internal WorkerConfig. Round-4 of Devin Review
	// on PR #41 (PR D) flagged that the previous wiring passed an
	// empty `integration.WorkerConfig{}`, which silently fell
	// back to the hard-coded defaults in
	// internal/service/integration/worker.go:46-65 — operators
	// who exported `INTEGRATION_WORKER_*` env vars would see them
	// validated at boot but never reach the live worker. Threads
	// the values through so the contract is honoured (mirrors the
	// webhook worker wiring above).
	integrationWorker := integration.NewDeliveryWorker(
		integrationConnectorRepo, integrationDeliveryRepo,
		integrationRegistry,
		integration.WorkerConfig{
			BatchSize:         cfg.Integration.BatchSize,
			PollInterval:      cfg.Integration.PollInterval,
			MaxAttempts:       cfg.Integration.MaxAttempts,
			BackoffBase:       cfg.Integration.BackoffBase,
			BackoffMax:        cfg.Integration.BackoffMax,
			ProcessingTimeout: cfg.Integration.ProcessingTimeout,
		},
		logger)

	// --- CASB wiring (Phase 4) ----------------------------------------
	casbHTTP := &http.Client{Timeout: 30 * time.Second}
	casbUA := cfg.AppName + "/sng-control"
	casbPlugins := casb.PluginRegistry{
		repository.CASBConnectorM365:       casbconnectors.NewM365(casbHTTP, casbUA),
		repository.CASBConnectorGoogle:     casbconnectors.NewGoogle(casbHTTP, casbUA),
		repository.CASBConnectorSlack:      casbconnectors.NewSlack(casbHTTP, casbUA),
		repository.CASBConnectorSalesforce: casbconnectors.NewSalesforce(casbHTTP, casbUA),
	}
	casbSvc := casb.New(
		casbConnectorRepo, casbAppRepo, casbPostureRepo, auditRepo,
		casbPlugins, logger)

	// --- MSP hierarchy wiring (Phase 3 Block 5) -----------------------
	// The MSP service is just the repository — there is no
	// business logic beyond what the repo already enforces.
	// Bulk operations need narrow adapters around policy / site /
	// identity services so the bulk package never imports their
	// concrete types.
	bulkPolicyApplier := policyTemplateApplierFunc(func(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
		return policySvc.PutGraph(ctx, tenantID, actorID, raw)
	})
	bulkSiteProvisioner := siteProvisionerFunc(func(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, s repository.Site) (repository.Site, error) {
		return siteSvc.Create(ctx, tenantID, actorID, s)
	})
	bulkTokenIssuer := claimTokenIssuerAdapter{identity: identitySvc}
	bulkSvc := tenant.NewBulkService(
		mspRepo, rbacSvc,
		bulkPolicyApplier, bulkSiteProvisioner, bulkTokenIssuer,
		logger, tenant.BulkOptions{})
	brandingResolver := tenant.NewBrandingResolver(tenantRepo, mspRepo)

	// --- Cost metering + budget guardrails (Session K) ---------------
	// The metering store is backed by the primary pool and adopts the
	// app role on every transaction so the RLS policies on
	// tenant_usage / tenant_budgets (migration 040) apply; per-tenant
	// work runs tenant-scoped, the background flush and the platform
	// cost report run system-scoped (sng.system_role), matching the
	// webhook delivery worker. The MeteringService accumulates usage in
	// sync/atomic counters and is flushed by main() via meteringSvc.Run.
	meteringStore, err := metering.NewPostgresStore(pool.Primary(), cfg.Postgres.AppRole, cfg.Postgres.PgBouncerMode)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("control: metering store: %w", err)
	}
	meteringSvc, err := metering.NewMeteringService(meteringStore, logger,
		metering.WithFlushInterval(cfg.Metering.FlushInterval))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("control: metering service: %w", err)
	}
	meteringTiers := meteringTierResolver{tenants: tenantRepo}
	budgetEnforcer, err := metering.NewBudgetEnforcer(meteringSvc, meteringStore, meteringTiers, logger,
		metering.WithGlobalDefaults(cfg.Metering.DefaultBudgets))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("control: budget enforcer: %w", err)
	}
	costCalc := metering.NewCostCalculator(metering.DefaultUnitCosts)
	meteringReports, err := metering.NewReports(meteringSvc, budgetEnforcer, meteringStore, meteringTiers, costCalc)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("control: metering reports: %w", err)
	}
	meteringHandler := handler.NewMeteringHandler(meteringSvc, budgetEnforcer, meteringReports, rbacSvc)

	aiHandler, aiSvc := buildAIHandler(cfg, policySvc, store.NewAICorrelationRepository(), alertRepo, auditSvc, aiSuggestionRepo,
		metering.NewGuardrailBudgetGate(budgetEnforcer), metering.NewGuardrailUsageRecorder(meteringSvc), logger)

	// --- Operational automation wiring (Session 5) --------------------
	// Bulk device operations reuse the existing device / claim-token /
	// enrollment repositories; ops-health is backed by its own snapshot
	// repository. Wiring here makes the /ops/health and /devices/bulk
	// + /devices/import|export routes actually serve in production.
	bulkDeviceSvc := identity.NewBulkDeviceService(deviceRepo, claimRepo, enrollmentRepo, auditRepo, logger)

	// --- Compliance + Playbook wiring (Session 1, Tasks 47, 49-54) ----
	// Compliance reporting renders per-tenant framework scores and
	// evidence packs from enforced-policy state. The playbook engine
	// runs remediation steps through the executor registry; both the
	// engine and its executors publish NATS commands via the same
	// adapter the alert router uses for `sng.<tenant>.alerts.*`.
	playbookPub := natsAlertAdapter{p: telPub}
	// SOC2 evidence automation (platform-level): signer + archive +
	// collector + scheduler. Wired additively so the report APIs work
	// unchanged; the scheduler's leader loop is launched by run().
	evidenceSvc, evidenceScheduler, err := buildEvidenceAutomation(cfg, store, logger)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("compliance evidence automation: %w", err)
	}
	complianceHandler := handler.NewComplianceHandler(
		compliance.NewReportService(store.NewComplianceReportRepository(), logger),
		handler.WithEvidenceAutomation(evidenceSvc, evidenceScheduler, rbacSvc))
	playbookEngine := playbook.NewEngine(
		store.NewPlaybookRepository(),
		store.NewPlaybookExecutionRepository(),
		playbookPub, logger)
	playbookEngine.SetExecutors(executors.NewRegistry(playbookPub))
	playbookApprovalSvc := playbook.NewApprovalService(
		store.NewPlaybookApprovalRepository(),
		store.NewPlaybookExecutionRepository(),
		logger)
	playbookHandler := handler.NewPlaybookHandler(playbookEngine, playbookApprovalSvc)

	// --- Troubleshoot wiring (Session 3, Tasks 61-66) ----------------
	// The autonomous troubleshooting assistant runs diagnostic checks
	// against tenant state, serves a global + per-tenant knowledge
	// base, and drives RAG-based suggest-only sessions over the same
	// LLM provider the AI handler uses (nil => deterministic templates
	// when no AI endpoint is configured).
	troubleshootChecks := []checks.DiagnosticCheck{
		checks.NewConnectivityCheck(deviceRepo, 0),
		checks.NewPolicyConsistencyCheck(policyRepo),
		checks.NewCertHealthCheck(deviceRepo, enrollmentRepo, 0),
		checks.NewIntegrationHealthCheck(integrationConnectorRepo),
		checks.NewPerformanceCheck(deviceRepo, 0),
	}
	troubleshootEngine := troubleshoot.NewDiagnosticEngine(troubleshootChecks)
	troubleshootKB := troubleshoot.NewKBService(store.NewKBEntryRepository())
	troubleshootAssistant := troubleshoot.NewAssistant(aiSvc.LLM(), troubleshootKB, troubleshootEngine)
	troubleshootSessions := troubleshoot.NewSessionService(
		store.NewTroubleshootSessionRepository(), troubleshootAssistant, nil)
	troubleshootHandler := handler.NewTroubleshootHandler(troubleshootSessions, troubleshootKB, troubleshootEngine)

	// --- Mobile IdP federation wiring (Session 5) --------------------
	// Per-tenant OIDC provider configs + the public mobile native-SSO
	// token/refresh endpoints. The OIDCService mints SNG sessions
	// signed with the same HMAC secret / iss / aud as operator-console
	// tokens so the standard auth middleware accepts them; the session
	// is bound to both the device key and the OIDC subject.
	idpConfigRepo := store.NewIDPConfigRepository()
	oidcSvc := identity.NewOIDCService(
		idpConfigRepo, userRepo, auditRepo,
		identity.SessionSigner{
			Secret:   []byte(cfg.Auth.JWTSecret),
			Issuer:   cfg.Auth.JWTIssuer,
			Audience: cfg.Auth.JWTAudience,
		},
		identity.OIDCOptions{
			SessionTTL:        cfg.MobileAuth.SessionTokenTTL,
			DiscoveryCacheTTL: cfg.MobileAuth.DiscoveryCacheTTL,
			AutoProvision:     cfg.MobileAuth.AutoProvisionUsers,
		},
		logger,
	)
	oidcHandler := handler.NewOIDCHandler(idpConfigRepo, oidcSvc, cfg.MobileAuth.MaxProvidersPerTenant)

	// --- Cloud PoP service (Session F) -------------------------------
	// The PoP store builds on the same ReadWritePool so its RLS GUC /
	// app-role semantics match the rest of the control plane. The
	// registry is a lock-free in-memory cache refreshed from Postgres
	// (Service.Run) and folded in real time by NATS health beacons.
	// The platform-admin routes are gated by the RBAC service's
	// AuthorizePlatform; the public bootstrap list needs no authority.
	popStore := pop.NewPostgresStore(pool)
	popRegistry := pop.NewRegistry(popStore, pop.WithHealthTTL(cfg.PoP.HealthTTL))
	popSvc := pop.NewService(popStore, popRegistry,
		pop.WithLogger(logger),
		pop.WithHighWaterFraction(cfg.PoP.HighWaterFraction),
	)
	popHandler := handler.NewPoPHandler(popSvc, rbacSvc)

	router := handler.NewRouter(handler.RouterDeps{
		Config:  cfg,
		Logger:  logger,
		Tenants: handler.NewTenantHandler(tenantSvc),
		Sites:   handler.NewSiteHandler(siteSvc),
		Devices: func() *handler.DeviceHandler {
			h := handler.NewDeviceHandler(identitySvc, deviceRepo, cfg.Auth.ClaimTokenTTL)
			h.SetEnrollmentService(enrollmentSvc)
			return h
		}(),
		RBAC:             handler.NewRBACHandler(rbacSvc),
		Policy:           handler.NewPolicyHandler(policySvc, policyKeySvc, policyHandlerOpts...),
		PolicySimulation: policySimHandler,
		Audit:            handler.NewAuditHandler(auditSvc),
		Webhooks:         handler.NewWebhookHandler(webhookSvc),
		APIKeys:          handler.NewAPIKeyHandler(apiKeySvc),
		Telemetry:        handler.NewTelemetryHandler(replay),
		AppRegistry:      appRegHandler,
		Baseline:         handler.NewBaselineHandler(baselineRepo, logger),
		Alert:            handler.NewAlertHandler(alertRouter, alertFeedback, logger),
		Integrations:     handler.NewIntegrationHandler(integrationSvc),
		CASB:             handler.NewCASBHandler(casbSvc),
		MSP:              handler.NewMSPHandler(mspRepo, bulkSvc, brandingResolver, rbacSvc),
		AI:               aiHandler,
		SCIM:             handler.NewSCIMHandler(scimSvc),
		Compliance:       complianceHandler,
		Playbook:         playbookHandler,
		Troubleshoot:     troubleshootHandler,
		OIDC:             oidcHandler,
		Mobile:           handler.NewMobileHandler(identitySvc),
		Metering:         meteringHandler,
		PoP:              popHandler,
		APIKeyLookup:     apiKeySvc,
		// Device kill-switch for stateless mobile session JWTs: a
		// token bound to a suspended/deleted device is refused by the
		// auth middleware on every endpoint, not just self-service.
		MobileDeviceStatus: mobileDeviceStatusCache.Resolver(handler.NewMobileDeviceStatusResolver(identitySvc)),
		Health:             health,
		OpenAPISpec:        handler.NewOpenAPIHandler(),
		OpsHealth:          handler.NewOpsHealthHandler(opsHealthRepo, logger),
		BulkDevice:         handler.NewBulkDeviceHandler(bulkDeviceSvc, deviceRepo, logger),
		Metrics:            mx,
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
	return router, webhookWorker, integrationWorker, appRegHandler, appSyncer, policySimHandler, aiSvc, meteringSvc, popSvc, evidenceScheduler, nil
}

// meteringTierResolver adapts the TenantRepository onto the metering
// TierResolver so the budget enforcer can resolve a tenant's
// commercial tier (and thus its default budgets). The lookup runs in
// the caller's request/worker context, so RLS applies as usual.
type meteringTierResolver struct {
	tenants repository.TenantRepository
}

func (m meteringTierResolver) TenantTier(ctx context.Context, tenantID uuid.UUID) (repository.TenantTier, error) {
	t, err := m.tenants.Get(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("metering: resolve tenant tier: %w", err)
	}
	return t.Tier, nil
}

// buildAIHandler constructs the AI handler with an optional LLM
// provider. When AI_LLM_ENDPOINT is not set, the service runs in
// template-only mode and suggest-policy / troubleshoot return 503.
func buildAIHandler(cfg *config.Config, policySvc *policy.Service, correlationRepo repository.AICorrelationRepository, alertRepo repository.AlertRepository, auditSvc *audit.Service, aiSuggestionRepo repository.AISuggestionRepository, budgetGate aisvc.BudgetGate, usageRecorder aisvc.UsageRecorder, logger *slog.Logger) (*handler.AIHandler, *aisvc.Service) {
	var llm aisvc.LLMProvider
	if cfg.AI.Endpoint != "" {
		llm = &aisvc.HTTPProvider{
			Endpoint: cfg.AI.Endpoint,
			APIKey:   cfg.AI.APIKey,
			Model:    cfg.AI.Model,
			Timeout:  cfg.AI.Timeout,
		}
		logger.Info("ai: LLM provider configured",
			slog.String("endpoint", cfg.AI.Endpoint),
			slog.String("model", cfg.AI.Model))
	} else {
		logger.Info("ai: no LLM endpoint configured; template-only mode")
	}

	var verifier *aisvc.Verifier
	if policySvc != nil {
		verifier = aisvc.NewVerifier(policySvc)
	}

	// Enhanced AI guardrails (Task 71). When a live LLM is configured
	// we wrap it once in a GuardrailedProvider so that EVERY AI code
	// path — the existing summarize/suggest/troubleshoot service as
	// well as the new correlation, NL-query and report engines — runs
	// through a single shared per-tenant rate limit, PII/secret
	// content filter, and audit log. When no endpoint is configured,
	// effectiveLLM stays nil and all AI features fall back to their
	// deterministic (template-only) behaviour. The guardrails handle
	// is also passed to the handler so the status endpoint can report
	// usage; it is nil (503) when no LLM is configured.
	var guardrails *aisvc.GuardrailedProvider
	var effectiveLLM aisvc.LLMProvider
	if llm != nil {
		var gopts []aisvc.GuardrailOption
		// When the audit service is available, persist every AI
		// interaction durably (in addition to the in-memory ring
		// buffer) so records survive restarts and are queryable for
		// compliance.
		if auditSvc != nil {
			gopts = append(gopts, aisvc.WithAuditSink(aiAuditSink{audit: auditSvc}))
		}
		// Cost-metering integration (Session K): gate every LLM call
		// on the tenant's token budget and meter actual consumption.
		// Both are best-effort with respect to availability — when
		// metering is not wired the args are nil and the guardrails
		// behave exactly as before.
		if budgetGate != nil {
			gopts = append(gopts, aisvc.WithBudgetGate(budgetGate))
		}
		if usageRecorder != nil {
			gopts = append(gopts, aisvc.WithUsageRecorder(usageRecorder))
		}
		guardrails = aisvc.NewGuardrailedProvider(llm, aisvc.GuardrailConfig{
			MaxRequestsPerMinute: cfg.AI.GuardrailMaxRequestsPerMinute,
			MaxTokensPerDay:      cfg.AI.GuardrailMaxTokensPerDay,
		}, logger, gopts...)
		effectiveLLM = guardrails
	}

	// Summarizer requires a ClickHouse evidence reader. For now,
	// we construct without one (nil) — it will be wired later via
	// svc.SetSummarizer when ClickHouse becomes available
	// (mirrors the policySimHandler.SetSimulator pattern).
	svc := aisvc.New(effectiveLLM, verifier, nil, aisvc.WithLogger(logger))
	h := handler.NewAIHandler(svc, logger)

	correlation := aisvc.NewCorrelationEngine(effectiveLLM, aisvc.CorrelationConfig{})
	// Wire the NL-query engine to the tenant's live compiled policy
	// graph so verdicts come from the real policy evaluator (the LLM
	// only ever parses intent, never produces the verdict). Falls
	// back to the heuristic default when policySvc is nil.
	var nlOpts []aisvc.NLQueryOption
	if policySvc != nil {
		nlOpts = append(nlOpts, aisvc.WithPolicyGraphSource(policySvc))
	}
	nlQuery := aisvc.NewNLQueryEngine(effectiveLLM, nlOpts...)
	reports := aisvc.NewReportEngine(effectiveLLM)
	// No external threat feed is configured by default; enrichment
	// returns an empty (non-escalated) context until one is wired.
	threatIntel := aisvc.NewThreatIntelEngine(nil)
	h.SetEnhancedAI(correlation, nlQuery, reports, threatIntel, guardrails, correlationRepo)

	// Back the read-only GET posture report with real alert counts so
	// it reflects actual posture rather than an empty baseline.
	if alertRepo != nil {
		h.SetPostureDataSource(alertPostureDataSource{alerts: alertRepo})
	}

	// Wire the policy-tightening suggestion features (Tasks 55-60).
	// The review service is backed by the ai_suggestions repository;
	// the tightening service is deterministic and only uses the LLM
	// (when configured) to polish rationales. Both are attached here
	// so the suggestion endpoints actually serve instead of returning
	// the unconfigured 503.
	if aiSuggestionRepo != nil {
		h.SetReviewService(aisvc.NewReviewService(aiSuggestionRepo, logger))
	}
	// Use effectiveLLM (the guardrailed wrapper when an LLM is
	// configured) so the tightening service's future LLM-polished
	// rationales run through the same per-tenant rate limit, content
	// filter, and audit log as every other AI path — rather than
	// silently bypassing guardrails with the raw provider.
	h.SetTighteningService(aisvc.NewTighteningService(effectiveLLM, logger))

	return h, svc
}

// alertPostureDataSource adapts the AlertRepository to the handler's
// PostureDataSource interface, counting alerts by severity within a
// reporting window. The repository returns rows in created-at DESC
// order, so once we page past the window start we can stop early,
// bounding the scan to alerts within the period (plus at most one
// extra page).
type alertPostureDataSource struct {
	alerts repository.AlertRepository
}

func (s alertPostureDataSource) AlertCountsBySeverity(ctx context.Context, tenantID uuid.UUID, start, end time.Time) (map[string]int, error) {
	counts := map[string]int{}
	page := repository.Page{Limit: repository.MaxPageLimit, Order: repository.SortDesc}
	for {
		res, err := s.alerts.List(ctx, tenantID, repository.AlertListFilter{}, page)
		if err != nil {
			return nil, err
		}
		stop := false
		for _, a := range res.Items {
			if a.CreatedAt.Before(start) {
				// DESC order: everything after this is older too.
				stop = true
				break
			}
			if a.CreatedAt.After(end) {
				continue
			}
			counts[string(a.Severity)]++
		}
		if stop || res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	return counts, nil
}

// aiAuditSink adapts the append-only audit service to the
// aisvc.AuditSink interface so guardrailed AI interactions are
// persisted durably. It maps an aisvc.AuditRecord onto an
// audit.Entry. Records without a tenant (uuid.Nil) are skipped:
// the audit log is tenant-scoped (RLS) and a nil tenant cannot be
// attributed or queried, so persisting it would be both rejected by
// the service and meaningless.
type aiAuditSink struct {
	audit *audit.Service
}

func (s aiAuditSink) RecordAIAudit(ctx context.Context, rec aisvc.AuditRecord) error {
	if rec.TenantID == uuid.Nil {
		return nil
	}
	details, err := json.Marshal(struct {
		Model      string `json:"model,omitempty"`
		TokenCount int    `json:"token_count"`
		LatencyMS  int64  `json:"latency_ms"`
		Redacted   bool   `json:"redacted"`
		Error      string `json:"error,omitempty"`
	}{
		Model:      rec.Model,
		TokenCount: rec.TokenCount,
		LatencyMS:  rec.LatencyMS,
		Redacted:   rec.Redacted,
		Error:      rec.Error,
	})
	if err != nil {
		return fmt.Errorf("marshal ai audit details: %w", err)
	}
	_, err = s.audit.Append(ctx, audit.Entry{
		TenantID:     rec.TenantID,
		Action:       "ai.llm." + rec.Action,
		ResourceType: "ai_guardrail",
		Details:      details,
	})
	return err
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
) (func(context.Context) error, handler.TelemetryClassQuerier, func() (policy.TelemetrySource, error), error) {
	var hot telemetry.HotWriter
	var cold telemetry.ColdWriter
	var hotStop func(context.Context) error
	var coldStop func(context.Context) error
	// chStats serves the /app-registry/stats endpoint; chReaderFactory
	// builds the policy simulator's read source. Both are nil when no
	// ClickHouse hot tier is configured, and both are satisfied by
	// either a single *chwriter.Writer or a *chwriter.ShardedWriter so
	// the rest of main is oblivious to the sharding mode.
	var chStats handler.TelemetryClassQuerier
	var chReaderFactory func() (policy.TelemetrySource, error)

	if len(cfg.TelemetryAnalytics.ClickHouseEndpoints) > 0 {
		chCfg := chwriter.Config{
			Endpoints:            cfg.TelemetryAnalytics.ClickHouseEndpoints,
			Database:             cfg.TelemetryAnalytics.ClickHouseDatabase,
			Table:                cfg.TelemetryAnalytics.ClickHouseTable,
			Username:             cfg.TelemetryAnalytics.ClickHouseUsername,
			Password:             cfg.TelemetryAnalytics.ClickHousePassword,
			TLS:                  cfg.TelemetryAnalytics.ClickHouseTLS,
			FlushInterval:        cfg.TelemetryAnalytics.ClickHouseFlushInterval,
			BatchSize:            cfg.TelemetryAnalytics.ClickHouseBatchSize,
			MaxBacklogMultiplier: cfg.TelemetryAnalytics.ClickHouseMaxBacklogMultiplier,
		}
		if cfg.TelemetryAnalytics.ClickHouseSharding {
			sw, err := chwriter.NewShardedWriter(ctx, chCfg, logger)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("clickhouse sharded writer: %w", err)
			}
			if cfg.TelemetryAnalytics.ClickHouseEnsureSchema {
				if err := sw.EnsureSchema(ctx); err != nil {
					_ = sw.Stop(ctx)
					return nil, nil, nil, fmt.Errorf("clickhouse schema: %w", err)
				}
			}
			hot = sw
			hotStop = sw.Stop
			chStats = sw
			chReaderFactory = func() (policy.TelemetrySource, error) { return sw.NewReader() }
			logger.Info("telemetry: clickhouse hot-path writer enabled (shard-aware)",
				slog.Int("shards", sw.ShardCount()),
				slog.String("endpoints", strings.Join(chCfg.Endpoints, ",")),
				slog.String("database", chCfg.Database),
				slog.String("table", chCfg.Table))
		} else {
			w, err := chwriter.New(ctx, chCfg, logger)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("clickhouse writer: %w", err)
			}
			if cfg.TelemetryAnalytics.ClickHouseEnsureSchema {
				if err := w.EnsureSchema(ctx); err != nil {
					_ = w.Stop(ctx)
					return nil, nil, nil, fmt.Errorf("clickhouse schema: %w", err)
				}
			}
			hot = w
			hotStop = w.Stop
			chStats = w
			chReaderFactory = func() (policy.TelemetrySource, error) { return w.NewReader() }
			logger.Info("telemetry: clickhouse hot-path writer enabled",
				slog.String("endpoints", strings.Join(chCfg.Endpoints, ",")),
				slog.String("database", chCfg.Database),
				slog.String("table", chCfg.Table))
		}
	}

	if cfg.TelemetryAnalytics.S3Bucket != "" {
		awsCfg, err := loadAWSConfig(ctx, cfg)
		if err != nil {
			if hotStop != nil {
				_ = hotStop(ctx)
			}
			return nil, nil, nil, fmt.Errorf("aws config: %w", err)
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
			return nil, nil, nil, fmt.Errorf("s3 writer: %w", err)
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
		return nil, nil, nil, fmt.Errorf("telemetry service: %w", err)
	}
	svc.WithDLQ(pub)
	if err := svc.Start(ctx); err != nil {
		if hotStop != nil {
			_ = hotStop(ctx)
		}
		if coldStop != nil {
			_ = coldStop(ctx)
		}
		return nil, nil, nil, fmt.Errorf("telemetry start: %w", err)
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
	return shutdown, chStats, chReaderFactory, nil
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

// Environment variables configuring the SOC2 evidence automation.
// Kept as direct env reads (not config.Config fields) so this change
// stays within the Session J file boundary and does not touch the
// shared config schema.
const (
	envEvidenceSigningKey = "COMPLIANCE_EVIDENCE_SIGNING_KEY_HEX"
	envEvidenceS3Bucket   = "COMPLIANCE_EVIDENCE_S3_BUCKET"
	envEvidenceS3Prefix   = "COMPLIANCE_EVIDENCE_S3_PREFIX"
)

// buildEvidenceAutomation wires the SOC2 evidence collector, signer,
// archive object store and scheduler. It is intentionally resilient to
// a partially-configured environment so the control plane still boots
// in dev/test:
//
//   - signing key: from COMPLIANCE_EVIDENCE_SIGNING_KEY_HEX (hex seed
//     or expanded key); a fresh ephemeral key with a loud warning when
//     unset (signatures then only verify within this process lifetime);
//   - archive: an S3 object store with 7-year object-lock retention
//     when COMPLIANCE_EVIDENCE_S3_BUCKET is set, else an in-memory
//     store (dev/test) with a warning.
//
// The collector's evidence sources are wired from the data that is
// genuinely platform-level and available at boot (the RBAC system-role
// catalog for CC6.1, and the HA topology for CC8.1). Per-tenant sources
// are intentionally left unwired; the scheduler's gap detection flags
// the missing controls rather than fabricating evidence.
func buildEvidenceAutomation(cfg *config.Config, store *postgres.Store, logger *slog.Logger) (*compliance.EvidenceService, *compliance.Scheduler, error) {
	signer, err := evidenceSigner(logger)
	if err != nil {
		return nil, nil, err
	}

	objStore, err := evidenceObjectStore(cfg, logger)
	if err != nil {
		return nil, nil, err
	}

	opts := []compliance.EvidenceServiceOption{}
	if prefix := strings.TrimSpace(os.Getenv(envEvidenceS3Prefix)); prefix != "" {
		opts = append(opts, compliance.WithKeyPrefix(prefix))
	}
	evidenceSvc, err := compliance.NewEvidenceService(
		store.NewComplianceEvidenceRepository(), objStore, signer, logger, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence service: %w", err)
	}

	collector := compliance.NewSOC2Collector(evidenceSources(cfg), logger)
	if err := collector.Validate(); err != nil {
		return nil, nil, err
	}

	scheduler, err := compliance.NewScheduler(collector, evidenceSvc, logger)
	if err != nil {
		return nil, nil, err
	}
	return evidenceSvc, scheduler, nil
}

// evidenceSigner builds the Ed25519 signer from configured key material
// or falls back to an ephemeral key.
func evidenceSigner(logger *slog.Logger) (*compliance.Signer, error) {
	raw := strings.TrimSpace(os.Getenv(envEvidenceSigningKey))
	if raw == "" {
		logger.Warn("compliance: no evidence signing key configured; generating an EPHEMERAL key — archived bundles will not verify after a restart",
			slog.String("env", envEvidenceSigningKey))
		return compliance.GenerateSigner()
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", envEvidenceSigningKey, err)
	}
	signer, err := compliance.NewSigner(key)
	if err != nil {
		return nil, fmt.Errorf("evidence signing key: %w", err)
	}
	logger.Info("compliance: evidence signing key loaded from configuration")
	return signer, nil
}

// evidenceObjectStore builds the archive sink: S3 with compliance
// object-lock retention when a bucket is configured, else an in-memory
// store for dev/test.
func evidenceObjectStore(cfg *config.Config, logger *slog.Logger) (compliance.ObjectStore, error) {
	bucket := strings.TrimSpace(os.Getenv(envEvidenceS3Bucket))
	if bucket == "" {
		logger.Warn("compliance: no evidence S3 bucket configured; archiving to an in-memory store — evidence is NOT durable",
			slog.String("env", envEvidenceS3Bucket))
		return compliance.NewMemoryObjectStore(), nil
	}
	awsCfg, err := loadAWSConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("evidence aws config: %w", err)
	}
	objStore, err := compliance.NewS3ObjectStore(s3.NewFromConfig(awsCfg), compliance.S3Config{
		Bucket: bucket,
	})
	if err != nil {
		return nil, fmt.Errorf("evidence s3 store: %w", err)
	}
	logger.Info("compliance: evidence archive enabled", slog.String("bucket", bucket))
	return objStore, nil
}

// evidenceSources wires the platform-level evidence exports the control
// plane can produce at boot. Sources that require tenant context are
// left nil and surface via gap detection.
func evidenceSources(cfg *config.Config) compliance.Sources {
	return compliance.Sources{
		// CC6.1 — the canonical platform RBAC role/permission catalog
		// is the logical-access policy of record.
		RBACPolicy: func(context.Context) (any, error) {
			return rbac.SystemRoles, nil
		},
		// CC8.1 — the control plane's high-availability topology:
		// active/active replicas coordinated by a Postgres
		// advisory-lock leader election.
		HAConfig: func(context.Context) (any, error) {
			return map[string]any{
				"model":                 "active-active-replicas",
				"leader_election":       "postgres-advisory-lock",
				"leader_check_interval": leader.DefaultCheckInterval.String(),
				"environment":           string(cfg.Environment),
				"singleton_workloads":   []string{"app-registry-sync", "compliance-evidence"},
				"database_failover":     "primary/replica pool",
			}, nil
		},
	}
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
func openPostgres(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*postgres.ReadWritePool, error) {
	primary, err := buildPgxPool(ctx, cfg, cfg.Postgres.DSN())
	if err != nil {
		return nil, fmt.Errorf("primary: %w", err)
	}
	// Fail boot if the primary is unreachable: the primary serves
	// every write, so a flapping readiness probe is preferable to a
	// process that starts but cannot persist anything.
	pingCtx, cancel := context.WithTimeout(ctx, cfg.Postgres.ConnTimeout)
	err = primary.Ping(pingCtx)
	cancel()
	if err != nil {
		primary.Close()
		return nil, fmt.Errorf("ping primary postgres: %w", err)
	}
	logger.Info("sng-control: postgres primary connected",
		slog.String("host", cfg.Postgres.Host),
		slog.Int("port", cfg.Postgres.Port),
		slog.String("database", cfg.Postgres.Database),
		slog.String("app_role", cfg.Postgres.AppRole),
		slog.Bool("pgbouncer_mode", cfg.Postgres.PgBouncerMode))

	// Read replicas are opened best-effort: a replica that is down
	// at boot is NOT a fatal error (the health-check loop evicts it
	// and Replica() falls back to the primary). We still fail boot
	// if a replica pool cannot even be *constructed* (e.g. a bad
	// DSN), since that is a config error, not a transient outage.
	var replicas []*pgxpool.Pool
	for _, host := range cfg.Postgres.ReadReplicaHosts {
		rp, rerr := buildPgxPool(ctx, cfg, cfg.Postgres.ReplicaDSN(host))
		if rerr != nil {
			primary.Close()
			for _, opened := range replicas {
				opened.Close()
			}
			return nil, fmt.Errorf("replica %s: %w", host, rerr)
		}
		replicas = append(replicas, rp)
		logger.Info("sng-control: postgres read replica configured",
			slog.String("host", host),
			slog.Int("port", cfg.Postgres.ReplicaPort()))
	}

	return postgres.NewReadWritePool(postgres.ReadWritePoolConfig{
		Primary:       primary,
		Replicas:      replicas,
		AppRole:       cfg.Postgres.AppRole,
		PgBouncerMode: cfg.Postgres.PgBouncerMode,
		Logger:        logger,
	}), nil
}

// buildPgxPool constructs (but does not ping) a single pgxpool.Pool
// from the given DSN, applying the shared connection-pool sizing and
// the role-adoption posture. It is used for both the primary and
// every read replica so they are configured identically.
func buildPgxPool(ctx context.Context, cfg *config.Config, dsn string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
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
	//      `permission denied` queries. This is exactly the case
	//      PG_PGBOUNCER_MODE addresses: when set, the session-level
	//      hook is skipped here and the repository layer adopts the
	//      role per-transaction via `SET LOCAL ROLE` instead.
	if cfg.Postgres.AppRole != "" && !cfg.Postgres.PgBouncerMode {
		poolCfg.AfterConnect = afterConnectSetRole(cfg.Postgres.AppRole)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
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

// popHealthBeacon is the JSON payload a PoP edge publishes on
// `sng.pop.<pop_id>.health`. The pop_id is carried in the subject
// (not the body) so the control plane can route the beacon without
// trusting a self-reported id in the payload.
type popHealthBeacon struct {
	ReportedAt        time.Time `json:"reported_at"`
	CPUPct            float64   `json:"cpu_pct"`
	MemoryPct         float64   `json:"memory_pct"`
	ActiveConnections int       `json:"active_connections"`
	BandwidthMbps     float64   `json:"bandwidth_mbps"`
}

// subscribePoPHealth wires the core-NATS subscription that folds PoP
// health beacons into the registry. Beacons are ephemeral,
// high-frequency telemetry, so they ride plain NATS pub/sub rather
// than a persisted JetStream stream: a missed beacon is self-healing
// (the next one arrives within the edge's report interval, and a PoP
// that goes silent ages out of the assignable set after the health
// TTL regardless).
func subscribePoPHealth(nc *nats.Conn, svc *pop.Service, logger *slog.Logger) (*nats.Subscription, error) {
	return nc.Subscribe("sng.pop.*.health", func(msg *nats.Msg) {
		// Subject shape: sng.pop.<pop_id>.health
		parts := strings.Split(msg.Subject, ".")
		if len(parts) != 4 {
			logger.Warn("pop: dropping health beacon with unexpected subject",
				slog.String("subject", msg.Subject))
			return
		}
		popID, err := uuid.Parse(parts[2])
		if err != nil {
			logger.Warn("pop: dropping health beacon with non-uuid pop id",
				slog.String("subject", msg.Subject), slog.Any("error", err))
			return
		}
		var b popHealthBeacon
		if err := json.Unmarshal(msg.Data, &b); err != nil {
			logger.Warn("pop: dropping malformed health beacon",
				slog.String("pop_id", popID.String()), slog.Any("error", err))
			return
		}
		h := pop.Health{
			PoPID:             popID,
			ReportedAt:        b.ReportedAt,
			CPUPct:            b.CPUPct,
			MemoryPct:         b.MemoryPct,
			ActiveConnections: b.ActiveConnections,
			BandwidthMbps:     b.BandwidthMbps,
		}
		// A dedicated short-lived context: IngestHealth does one INSERT
		// plus an in-memory fold, and the message callback must not
		// block the NATS dispatcher indefinitely if Postgres stalls.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := svc.IngestHealth(ctx, h); err != nil {
			logger.Warn("pop: ingest health beacon failed",
				slog.String("pop_id", popID.String()), slog.Any("error", err))
		}
	})
}

// runPoPRebalance drives the leader-only capacity rebalancer until ctx
// is cancelled. It is invoked through elector.RunIfLeader, so it both
// starts on leadership acquisition and returns (stopping the ticker)
// when leadership is lost or the process shuts down.
func runPoPRebalance(ctx context.Context, svc *pop.Service, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			moved, err := svc.Rebalance(ctx)
			if err != nil && ctx.Err() == nil {
				logger.Warn("pop: rebalance pass failed", slog.Any("error", err))
				continue
			}
			if moved > 0 {
				logger.Info("pop: rebalance moved tenants off overloaded PoPs",
					slog.Int("moved", moved))
			}
		}
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

// natsAlertAdapter adapts sngnats.Publisher (Publish takes 4
// args including PublishOptions) to the alert.Router.Publisher
// interface (Publish takes 3 args). The Router treats alert
// publishing as best-effort fire-and-forget — a transient NATS
// hiccup must not roll back the persistent alert row — so we
// use the publisher's default retry/timeout from cfg.NATS
// (PublishOptions{} = zero-value = use cfg defaults).
type natsAlertAdapter struct {
	p *sngnats.Publisher
}

func (a natsAlertAdapter) Publish(ctx context.Context, subject string, data []byte) error {
	if a.p == nil {
		return nil
	}
	return a.p.Publish(ctx, subject, data, sngnats.PublishOptions{})
}

// hostnameForSyslog returns the local hostname used as the
// HOSTNAME field in RFC 5424 syslog frames. Falls back to
// "sng-control" so a hostname-lookup failure does not crash the
// connector; operators see the literal "sng-control" in their
// SIEM and can correlate against the Kubernetes pod metadata.
func hostnameForSyslog() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "sng-control"
	}
	return h
}

// --- MSP bulk-operation adapters ------------------------------------
//
// The tenant.BulkService talks to small interfaces (PolicyTemplateApplier,
// SiteProvisioner, ClaimTokenIssuer) so the bulk package never imports
// the policy / site / identity packages directly. These adapters bridge
// the concrete service methods to those interfaces.

type policyTemplateApplierFunc func(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error)

func (f policyTemplateApplierFunc) PutGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error) {
	return f(ctx, tenantID, actorID, raw)
}

type siteProvisionerFunc func(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, s repository.Site) (repository.Site, error)

func (f siteProvisionerFunc) Create(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, s repository.Site) (repository.Site, error) {
	return f(ctx, tenantID, actorID, s)
}

// claimTokenIssuerAdapter wraps *identity.Service so its
// GenerateClaimToken (which returns identity.GenerateClaimTokenResult)
// can satisfy tenant.ClaimTokenIssuer (which expects the slimmer
// tenant.ClaimTokenResult).
type claimTokenIssuerAdapter struct {
	identity *identity.Service
}

func (a claimTokenIssuerAdapter) GenerateClaimToken(ctx context.Context, tenantID uuid.UUID, ttl time.Duration, createdBy *uuid.UUID) (tenant.ClaimTokenResult, error) {
	res, err := a.identity.GenerateClaimToken(ctx, tenantID, ttl, createdBy)
	if err != nil {
		return tenant.ClaimTokenResult{}, err
	}
	return tenant.ClaimTokenResult{
		Plaintext: res.Plaintext,
		ExpiresAt: res.Token.ExpiresAt,
	}, nil
}
