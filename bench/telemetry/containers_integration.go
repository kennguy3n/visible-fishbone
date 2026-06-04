//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	natsstreams "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// publisher is the subset of jetstream.JetStream the live benches use
// to publish telemetry envelopes; an interface so helpers stay testable
// and decoupled from the concrete context.
type publisher interface {
	Publish(ctx context.Context, subject string, payload []byte, opts ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// publishEnvelope marshals env and publishes it on its canonical
// telemetry subject.
func publishEnvelope(ctx context.Context, js publisher, env schema.Envelope) error {
	wire, err := schema.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	subj := natsstreams.SubjectForTelemetry(env.TenantID.String(), string(env.EventClass))
	if _, err := js.Publish(ctx, subj, wire); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// containers_integration.go holds the ephemeral-infrastructure helpers
// the live benches share: an in-process JetStream server (no Docker
// needed), a ClickHouse container, and a MinIO (S3-compatible)
// container. All are torn down by the returned cleanup func.

const (
	clickHouseImage = "clickhouse/clickhouse-server:24.3-alpine"
	minioImage      = "minio/minio:RELEASE.2024-05-28T17-19-04Z"
	minioAccessKey  = "minioadmin"
	minioSecretKey  = "minioadmin"
)

// embeddedNATS boots an in-process JetStream-enabled NATS server bound
// to a random port, mirroring the production wiring closely enough for
// throughput work. Returns the connection, a JetStream context, and a
// cleanup func.
func embeddedNATS() (*nats.Conn, jetstream.JetStream, func(), error) {
	dir, err := os.MkdirTemp("", "sng-bench-jetstream-")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jetstream store dir: %w", err)
	}
	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1,
		JetStream:      true,
		StoreDir:       dir,
		HTTPPort:       -1,
		NoSigs:         true,
		MaxControlLine: 4096,
		// Generous payload + store so a high-rate burst does not trip
		// the default 1 MiB max payload or a tiny store.
		MaxPayload:         4 * 1024 * 1024,
		JetStreamMaxMemory: 1 << 30,
		JetStreamMaxStore:  4 << 30,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new nats server: %w", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		return nil, nil, nil, fmt.Errorf("nats server not ready in 10s")
	}
	nc, err := nats.Connect(srv.ClientURL(), nats.Timeout(5*time.Second))
	if err != nil {
		srv.Shutdown()
		return nil, nil, nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		srv.Shutdown()
		return nil, nil, nil, fmt.Errorf("jetstream: %w", err)
	}
	cleanup := func() {
		nc.Close()
		srv.Shutdown()
		srv.WaitForShutdown()
		_ = os.RemoveAll(dir)
	}
	return nc, js, cleanup, nil
}

// startClickHouse boots a ClickHouse container and returns its native
// (9000) endpoint as host:port plus a cleanup func.
func startClickHouse(ctx context.Context) (string, func(), error) {
	req := testcontainers.ContainerRequest{
		Image:        clickHouseImage,
		ExposedPorts: []string{"9000/tcp", "8123/tcp"},
		Env: map[string]string{
			"CLICKHOUSE_DB":                        "default",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		WaitingFor: wait.ForHTTP("/ping").
			WithPort("8123/tcp").
			WithStartupTimeout(90 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", nil, fmt.Errorf("start clickhouse: %w", err)
	}
	cleanup := func() { _ = c.Terminate(ctx) }
	host, err := c.Host(ctx)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("clickhouse host: %w", err)
	}
	port, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("clickhouse port: %w", err)
	}
	return fmt.Sprintf("%s:%s", host, port.Port()), cleanup, nil
}

// startMinIO boots a MinIO container and returns an S3 client wired to
// it (path-style, static creds) plus a cleanup func. The caller creates
// whatever buckets it needs.
func startMinIO(ctx context.Context) (*awss3.Client, func(), error) {
	req := testcontainers.ContainerRequest{
		Image:        minioImage,
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     minioAccessKey,
			"MINIO_ROOT_PASSWORD": minioSecretKey,
		},
		Cmd: []string{"server", "/data"},
		WaitingFor: wait.ForHTTP("/minio/health/ready").
			WithPort("9000/tcp").
			WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start minio: %w", err)
	}
	cleanup := func() { _ = c.Terminate(ctx) }
	host, err := c.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("minio host: %w", err)
	}
	port, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("minio port: %w", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())
	client := awss3.New(awss3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials:  credentials.NewStaticCredentialsProvider(minioAccessKey, minioSecretKey, ""),
		UsePathStyle: true,
	})
	return client, cleanup, nil
}
