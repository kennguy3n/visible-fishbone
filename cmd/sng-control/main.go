// Command sng-control is the ShieldNet Gateway control-plane service
// entrypoint. It loads configuration from the environment, opens
// connections to NATS and PostgreSQL, and serves the operator HTTP
// API alongside health and readiness probes.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
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

	nc, err := openNATS(&cfg, logger)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer func() {
		if err := nc.Drain(); err != nil {
			logger.Warn("sng-control: nats drain error", slog.Any("error", err))
		}
	}()

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

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", health.Liveness)
	mux.HandleFunc("/readyz", health.Readiness)

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr(),
		Handler:           mux,
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

	logger.Info("sng-control: stopped")
	return nil
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
	poolCfg.MaxConns = int32(cfg.Postgres.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.Postgres.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.Postgres.ConnMaxLifetime
	poolCfg.ConnConfig.ConnectTimeout = cfg.Postgres.ConnTimeout

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
		slog.String("database", cfg.Postgres.Database))
	return pool, nil
}

// openNATS connects to the NATS cluster and verifies JetStream is
// reachable. The control plane is not useful without JetStream, so
// a missing stream context fails boot rather than degrading
// silently.
func openNATS(cfg *config.Config, logger *slog.Logger) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name(cfg.NATS.Name),
		nats.ReconnectWait(cfg.NATS.ReconnectWait),
		nats.MaxReconnects(cfg.NATS.MaxReconnects),
		nats.Timeout(cfg.NATS.RequestTimeout),
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

	nc, err := nats.Connect(cfg.NATS.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if _, err := nc.JetStream(); err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	logger.Info("sng-control: nats connected",
		slog.String("url", cfg.NATS.URL),
		slog.String("stream_prefix", cfg.NATS.StreamPrefix))
	return nc, nil
}
