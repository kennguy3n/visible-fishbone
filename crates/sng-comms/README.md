# sng-comms

ShieldNet Gateway (SNG) native protocol client. `sng-comms` is the
single transport library shared by the edge VM appliance
(`sng-edge`) and the endpoint agent (`sng-agent`) for communicating
with the control plane.

## Wire shape

* **Transport**: TLS 1.3 (rustls, no OpenSSL) with mutual TLS
  authentication. Device identity is bound to an Ed25519 keypair —
  the same curve the policy-bundle signer uses on the control-plane
  side, so a single key-management surface covers both transport
  authentication and bundle verification.
* **Framing**: HTTP/2 (h2 crate, ALPN `h2` per RFC 7540 §3.3) with
  flow-controlled streams. Connections are long-lived; the client
  multiplexes batches across HTTP/2 streams rather than opening
  one TCP connection per batch.
* **Encoding**: MessagePack (rmp-serde) end-to-end. Matches the Go
  control plane's `vmihailenco/msgpack/v5` codec at
  `internal/nats/schema/envelope.go`.
* **Compression**: zstd on telemetry batches before they're framed
  onto an HTTP/2 stream. Policy-bundle payloads are pulled raw — the
  control plane already emits the compiled bundle as a tight
  MessagePack blob that gzip's further on the way to the agent via
  HTTP/2 frame-level compression hints, so an extra application-
  level codec on the pull path is double work.

## Surfaces

* [`ControlPlaneClient`](src/client.rs) — connection lifecycle:
  `connect`, `send_request`, reconnect with exponential backoff +
  jitter.
* [`PolicyPuller`](src/policy.rs) — `GET /api/v1/tenants/{tid}/policy/bundles/{target}/payload`
  with `If-None-Match` cache validation, Ed25519 signature
  verification against a [`PolicyTrustStore`](src/policy.rs), and
  version monotonicity tracking. On `304 Not Modified` the cached
  bundle is reused without re-decoding the body.
* [`TelemetryClient`](src/telemetry.rs) — batch submission of
  [`Envelope`](sng-core/src/envelope.rs) over the native protocol.
  Metadata-first redaction: payloads are stripped unless the
  per-flow policy opts in. Local enrichment hooks for site / tenant /
  time / identity binding run on the submission path so the egress
  bytes always carry the agent's authoritative view.
* [`BatchBuilder`](src/batch.rs) — size-and-time-bounded batching.
* [`BoundedSpool`](src/spool.rs) — bounded local in-memory spool;
  oldest-dropped-first on overflow. (Disk-backed spool is layered
  on top by `sng-telemetry`.)
* [`SequenceTracker`](src/ack.rs) — monotonic per-stream sequence
  numbers; ack regression triggers a fail-closed reconnect.

## Mock server

The integration tests stand up an in-process `rustls`-backed HTTP/2
server bound to `127.0.0.1:0` and mint a self-signed CA + leaf
certificate via `rcgen` per-test. The server speaks the same
content-type / signature header / ETag conventions as the Go
control plane so the client implementation is exercised against
the exact wire shape it will see in production.
