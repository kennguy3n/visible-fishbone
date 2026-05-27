package nats_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// startEmbeddedNATS boots an in-process JetStream-enabled NATS
// server. Returns the *nats.Conn ready for use, plus a cleanup
// function the test should defer. The server is bound to a random
// port and uses a per-test JetStream store dir under t.TempDir(),
// so parallel-running tests do not collide.
func startEmbeddedNATS(t *testing.T) (*nats.Conn, jetstream.JetStream) {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "jetstream")
	opts := &natsserver.Options{
		Host:           "127.0.0.1",
		Port:           -1, // -1 picks any free port
		JetStream:      true,
		StoreDir:       dir,
		DontListen:     false,
		HTTPPort:       -1,
		NoSigs:         true,
		MaxControlLine: 4096,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new nats server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatalf("nats server not ready in 5s")
	}
	t.Cleanup(func() {
		srv.Shutdown()
		srv.WaitForShutdown()
	})

	nc, err := nats.Connect(srv.ClientURL(), nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(func() { nc.Close() })

	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	// Quick round-trip to confirm JetStream is alive.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := js.AccountInfo(ctx); err != nil {
		t.Fatalf("jetstream account info: %v", err)
	}
	return nc, js
}
