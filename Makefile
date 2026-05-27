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
lint-go:
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
		$(CARGO) clippy --workspace --all-targets -- -D warnings; \
	else \
		echo "lint-rust: Cargo.toml not present yet; skipping"; \
	fi

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

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out
	@if [ -d target ]; then $(CARGO) clean; fi
