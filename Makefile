# ShieldNet Gateway (SNG) Makefile
#
# Combined Go + Rust workspace targets. The Go targets drive the
# control-plane binary (`cmd/sng-control`); the Rust targets drive the
# endpoint client workspace (`crates/`). The combined `build`,
# `test`, and `lint` targets fan out to both stacks so a single
# command verifies the whole tree.

GO              ?= go
CARGO           ?= cargo
GOTEST_FLAGS    ?= -race -timeout 120s
BIN_DIR         ?= bin
APP_NAME        ?= sng-control
MIGRATIONS_DIR  ?= migrations
DOCKER_COMPOSE  ?= docker compose

# --- Top-level convenience -------------------------------------------------

.PHONY: all
all: lint test build

.PHONY: help
help:
	@echo "SNG developer Makefile"
	@echo ""
	@echo "Go targets:"
	@echo "  build-go            Build the sng-control binary"
	@echo "  run                 Run sng-control via 'go run'"
	@echo "  test-go             Race-enabled Go unit tests"
	@echo "  test-integration    Race-enabled Go integration tests (build tag 'integration')"
	@echo "  cover               Coverage report"
	@echo "  lint-go             golangci-lint + go vet"
	@echo "  fmt                 gofmt"
	@echo "  tidy                go mod tidy"
	@echo ""
	@echo "Rust targets:"
	@echo "  build-rust          cargo build --workspace"
	@echo "  test-rust           cargo test --workspace"
	@echo "  lint-rust           cargo fmt --check + cargo clippy"
	@echo ""
	@echo "Throughput benchmarks (bench/ workspace):"
	@echo "  bench-build         cargo build --release (sng-bench harness)"
	@echo "  bench-test          cargo test (sng-bench harness)"
	@echo "  bench-lint          cargo fmt --check + cargo clippy (sng-bench)"
	@echo "  bench-regression    Micro-SKU forwarding regression gate vs committed baseline"
	@echo ""
	@echo "Combined:"
	@echo "  build               build-go + build-rust"
	@echo "  test                test-go + test-rust"
	@echo "  lint                lint-go + lint-rust"
	@echo ""
	@echo "Infra / migrations:"
	@echo "  docker-up           docker compose up -d"
	@echo "  docker-down         docker compose down"
	@echo "  migrate-up          Apply migrations"
	@echo "  migrate-down        Roll back one migration"
	@echo "  migrate-status      Print migration status"
	@echo "  migrate-check       Verify migration versions are unique+contiguous (no DB)"

# --- Go --------------------------------------------------------------------

.PHONY: build-go
build-go:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

.PHONY: run
run:
	$(GO) run ./cmd/$(APP_NAME)

.PHONY: test-go
test-go:
	$(GO) test $(GOTEST_FLAGS) ./...

.PHONY: test-integration
test-integration:
	$(GO) test $(GOTEST_FLAGS) -tags=integration ./...

.PHONY: cover
cover:
	$(GO) test $(GOTEST_FLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

.PHONY: lint-go
lint-go: migrate-check
	$(GO) vet ./...
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: tidy
tidy:
	$(GO) mod tidy

# --- Rust ------------------------------------------------------------------

# The Rust workspace lands in PR 7. Until then, these targets degrade
# gracefully when crates/ does not exist so the combined `make test`
# target stays green for Go-only development.

.PHONY: build-rust
build-rust:
	@if [ -f Cargo.toml ]; then \
		$(CARGO) build --workspace; \
	else \
		echo "build-rust: Cargo.toml not present yet; skipping"; \
	fi

.PHONY: test-rust
test-rust:
	@if [ -f Cargo.toml ]; then \
		$(CARGO) test --workspace; \
	else \
		echo "test-rust: Cargo.toml not present yet; skipping"; \
	fi

.PHONY: lint-rust
lint-rust:
	@if [ -f Cargo.toml ]; then \
		$(CARGO) fmt --all -- --check && \
		$(CARGO) clippy --workspace --all-targets -- -D warnings && \
		if command -v cargo-deny >/dev/null 2>&1; then \
			$(CARGO) deny --all-features check; \
		else \
			echo "lint-rust: cargo-deny not installed; skipping (install with: cargo install --locked cargo-deny)"; \
		fi; \
	else \
		echo "lint-rust: Cargo.toml not present yet; skipping"; \
	fi

# --- Throughput benchmarks (WS3) -------------------------------------------
# The forwarding-benchmark harness lives in its own Cargo workspace under
# bench/ (excluded from the root workspace: it pulls the enforcement crates
# in as path deps and ships its own binaries), so the build/test/lint-rust
# targets above — which run `--workspace` against the root manifest — never
# touch it. These targets gate it explicitly, and the CI
# throughput-regression job calls `bench-regression` so local == CI.
BENCH_MANIFEST   := bench/Cargo.toml
BENCH_BIN        := bench/target/release/sng-bench
MICRO_PROFILE    := bench/profiles/skus/micro.toml
MICRO_BASELINE   := bench/results/forwarding-micro.json
# Written under bench/target/ (gitignored) so the gate leaves no untracked
# files behind.
MICRO_CURRENT    := bench/target/forwarding-micro.current.json
# Maximum tolerated drift in the hardware-invariant ratios before the gate
# fails the build. 15% absorbs runner noise while still catching a real
# per-stage cost or fast-path-advantage regression.
BENCH_THRESHOLD  := 0.15

.PHONY: bench-lint
bench-lint:
	$(CARGO) fmt --manifest-path $(BENCH_MANIFEST) --all -- --check
	$(CARGO) clippy --manifest-path $(BENCH_MANIFEST) --all-targets -- -D warnings

.PHONY: bench-test
bench-test:
	$(CARGO) test --manifest-path $(BENCH_MANIFEST) --all-targets

.PHONY: bench-build
bench-build:
	$(CARGO) build --release --manifest-path $(BENCH_MANIFEST)

# Forwarding-throughput regression gate (Micro SKU). Re-runs the sweep on
# this host and compares hardware-invariant ratios against the committed
# baseline; the compare exits non-zero (code 2) and fails the build if any
# mode/backend regresses beyond BENCH_THRESHOLD. Refresh the baseline
# deliberately (see docs/throughput-skus.md) for an intentional change.
.PHONY: bench-regression
bench-regression: bench-build
	$(BENCH_BIN) forwarding --profile $(MICRO_PROFILE) --out $(MICRO_CURRENT)
	$(BENCH_BIN) forwarding-compare \
		--baseline $(MICRO_BASELINE) \
		--current $(MICRO_CURRENT) \
		--threshold $(BENCH_THRESHOLD)

# --- Combined --------------------------------------------------------------

.PHONY: build
build: build-go build-rust

.PHONY: test
test: test-go test-rust

.PHONY: lint
lint: lint-go lint-rust

# --- Infrastructure --------------------------------------------------------

.PHONY: docker-up
docker-up:
	$(DOCKER_COMPOSE) up -d

.PHONY: docker-down
docker-down:
	$(DOCKER_COMPOSE) down

.PHONY: docker-logs
docker-logs:
	$(DOCKER_COMPOSE) logs -f

# --- Migrations ------------------------------------------------------------

# Migration tooling: golang-migrate v4 driven by the embedded
# `cmd/sng-migrate` binary. The binary reads PG_* env vars from the
# same .env that sng-control consumes, so a single `direnv allow`
# (or `set -a; source .env; set +a`) is enough to wire everything.

.PHONY: build-migrate
build-migrate:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/sng-migrate ./cmd/sng-migrate

.PHONY: migrate-up
migrate-up: build-migrate
	$(BIN_DIR)/sng-migrate up

.PHONY: migrate-down
migrate-down: build-migrate
	$(BIN_DIR)/sng-migrate down 1

.PHONY: migrate-status
migrate-status: build-migrate
	$(BIN_DIR)/sng-migrate status

# migrate-check is the structural guard over the migration set:
# unique + contiguous version numbers with paired up/down files. It
# needs no database (it only reads filenames), so it runs as part of
# `lint-go` and mirrors the `check-versions` step in CI's lint job —
# catching the merge-order collision where two branches both add the
# next free version number.
.PHONY: migrate-check
migrate-check:
	$(GO) run ./cmd/sng-migrate check-versions

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out
	@if [ -d target ]; then $(CARGO) clean; fi

# --- UI (Admin / MSP portal) -----------------------------------------------
#
# Self-contained targets for the Vite + React + TypeScript admin UI under
# ui/. They are intentionally decoupled from the Go/Rust targets above so
# the combined `build`/`lint`/`test` targets do not require Node tooling on
# control-plane-only machines. Run `make ui-build` (etc.) explicitly.

UI_DIR    ?= ui
NPM       ?= npm
UI_IMAGE  ?= sng-ui:dev

.PHONY: ui-install
ui-install:
	cd $(UI_DIR) && $(NPM) install

.PHONY: ui-gen-api
ui-gen-api:
	cd $(UI_DIR) && $(NPM) run gen:api

.PHONY: ui-dev
ui-dev:
	cd $(UI_DIR) && $(NPM) run dev

.PHONY: ui-lint
ui-lint:
	cd $(UI_DIR) && $(NPM) run lint

.PHONY: ui-typecheck
ui-typecheck:
	cd $(UI_DIR) && $(NPM) run typecheck

.PHONY: ui-build
ui-build:
	cd $(UI_DIR) && $(NPM) run build

.PHONY: ui-docker
ui-docker:
	cd $(UI_DIR) && docker build -t $(UI_IMAGE) .
