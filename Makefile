BINARY_SERVER  := bin/clavex
BINARY_MIGRATE := bin/migrate
BINARY_CTL     := bin/clavexctl
BINARY_SHIELD  := bin/shield-feed
BINARY_REGMON  := bin/regulatory-monitor
GO_FLAGS      := -ldflags="-s -w"
GOTEST        := go test ./... -race -count=1
NODE          ?= $(shell command -v node 2>/dev/null || echo "/home/fabio/.nvm/versions/node/v22.17.0/bin/node")
NPM           ?= $(dir $(NODE))npm

.PHONY: all build build-backend build-frontend run dev migrate-up migrate-down migrate-version \
        docker-build docker-up docker-down test lint fmt tidy clean openapi-check openapi-update \
        clavexctl shield-feed shield-feed-key shield-feed-deploy regulatory-monitor

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

build: build-backend build-frontend

build-backend: tidy
	@mkdir -p bin
	go build $(GO_FLAGS) -o $(BINARY_SERVER) ./cmd/server
	go build $(GO_FLAGS) -o $(BINARY_MIGRATE) ./cmd/migrate
	go build $(GO_FLAGS) -o $(BINARY_CTL)    ./cmd/clavexctl

## shield-feed — build the Shield aggregator microservice binary
shield-feed:
	@mkdir -p bin
	go build $(GO_FLAGS) -o $(BINARY_SHIELD) ./cmd/shield-feed
	@echo "Built $(BINARY_SHIELD)"

## regulatory-monitor — build the AI Regulatory Change Monitor binary
regulatory-monitor:
	@mkdir -p bin
	go build $(GO_FLAGS) -o $(BINARY_REGMON) ./cmd/regulatory-monitor
	@echo "Built $(BINARY_REGMON)"

## shield-feed-key — generate EC P-256 signing key for the Shield feed
shield-feed-key:
	@mkdir -p keys
	@if [ -f keys/shield-signing.pem ]; then \
		echo "keys/shield-signing.pem already exists — delete it first to regenerate"; \
	else \
		openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | \
			openssl pkcs8 -topk8 -nocrypt -out keys/shield-signing.pem 2>/dev/null && \
		chmod 600 keys/shield-signing.pem && \
		echo "Generated: keys/shield-signing.pem (EC P-256)" && \
		echo "Public key (for SHIELD_SIGNING_PUB_KEY / config):" && \
		openssl ec -in keys/shield-signing.pem -pubout 2>/dev/null; \
	fi

## shield-feed-deploy — deploy to fly.io (requires flyctl)
shield-feed-deploy:
	flyctl deploy --config cmd/shield-feed/fly.toml --dockerfile Dockerfile.shield-feed

## clavexctl — build only the admin CLI
clavexctl:
	@mkdir -p bin
	go build $(GO_FLAGS) -o $(BINARY_CTL) ./cmd/clavexctl
	@echo "Built $(BINARY_CTL)  — run: CLAVEX_SERVER=https://… CLAVEX_TOKEN=… ./$(BINARY_CTL) orgs list"

# ── Frontend ──────────────────────────────────────────────────────────────────

build-frontend:
	@echo "Building frontend…"
	cd frontend && $(NPM) ci --silent && $(NPM) run build
	@echo "Frontend built → build/frontend/"

frontend-dev:
	cd frontend && $(NPM) run dev

# ── Run ───────────────────────────────────────────────────────────────────────

run: build
	./$(BINARY_SERVER)

dev:
	CLAVEX_DEV=true go run ./cmd/server --config config.dev.yaml

# ── Database migrations ───────────────────────────────────────────────────────
# Picks config.dev.yaml when present (local dev), falls back to config.yaml.
MIGRATE_CFG ?= $(if $(wildcard config.dev.yaml),config.dev.yaml,config.yaml)

migrate-up: build-backend
	./$(BINARY_MIGRATE) -config $(MIGRATE_CFG) up

migrate-down: build-backend
	./$(BINARY_MIGRATE) -config $(MIGRATE_CFG) down $(STEPS)

migrate-version: build-backend
	./$(BINARY_MIGRATE) -config $(MIGRATE_CFG) version

# Create a new migration pair: make migrate-new NAME=add_something
migrate-new:
	@[ -n "$(NAME)" ] || (echo "Usage: make migrate-new NAME=<description>"; exit 1)
	$(eval VERSION := $(shell printf '%06d' $$(ls internal/db/migrations/*.up.sql 2>/dev/null | wc -l | tr -d ' ' | awk '{print $$1+1}')))
	@touch internal/db/migrations/$(VERSION)_$(NAME).up.sql
	@touch internal/db/migrations/$(VERSION)_$(NAME).down.sql
	@echo "Created:"
	@echo "  internal/db/migrations/$(VERSION)_$(NAME).up.sql"
	@echo "  internal/db/migrations/$(VERSION)_$(NAME).down.sql"

# ── Keys ─────────────────────────────────────────────────────────────────────

# Generates a 4096-bit RSA signing key (PKCS#8 PEM) under ./keys/signing.pem
generate-keys:
	@mkdir -p keys
	@if [ -f keys/signing.pem ]; then \
		echo "keys/signing.pem already exists — delete it first to regenerate"; \
	else \
		openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
			-out keys/signing.pem 2>/dev/null && \
		chmod 600 keys/signing.pem && \
		echo "Generated: keys/signing.pem (RSA 4096)"; \
	fi

# ── First-run seed ────────────────────────────────────────────────────────────

# Creates an initial org + admin user.  Reads connection from env or config.yaml.
# Usage: make seed ORG=myorg EMAIL=admin@example.com PASSWORD=changeme
seed: build-backend
	./$(BINARY_MIGRATE) up
	go run ./cmd/seed \
		-org="$(or $(ORG),demo)" \
		-email="$(or $(EMAIL),admin@demo.local)" \
		-password="$(or $(PASSWORD),Admin1234!)"

# ── Docker ────────────────────────────────────────────────────────────────────

docker-build:
	docker build -t clavex:dev .

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f clavex

# ── eIDAS node integration test (CEF Digital demo environment) ────────────────
#
# The European Commission provides a publicly accessible eIDAS test node at:
#   https://eidas.ec.europa.eu/EidasNode/ColleagueRequest
#
# This makes it possible to verify Clavex is compatible with the real eIDAS
# network without registering with a national node operator first.
#
# Pre-requisites:
#   1. Clavex is running and reachable over HTTPS (ngrok / cloudflared works).
#   2. eIDAS config created for the org via PUT /api/v1/organizations/:org_id/eidas.
#   3. SP metadata submitted to https://eidas.ec.europa.eu/EidasNode once.
#
# Workflow:
#   make eidas-metadata ORG=<org_slug>    — download SP metadata XML to submit
#   make eidas-test-url ORG=<org_slug>    — print the SSO URL to open in browser
#
CEF_NODE_URL := https://eidas.ec.europa.eu/EidasNode/ColleagueRequest
CLAVEX_BASE  ?= http://localhost:8080

.PHONY: eidas-metadata eidas-test-url

eidas-metadata:
	@[ -n "$(ORG)" ] || (echo "Usage: make eidas-metadata ORG=<org_slug>"; exit 1)
	@echo "Downloading SP metadata for org '$(ORG)'…"
	@curl -fsSL "$(CLAVEX_BASE)/api/v1/organizations/$(ORG)/eidas/metadata" \
		-o sp-metadata-$(ORG).xml
	@echo "Saved → sp-metadata-$(ORG).xml"
	@echo "Submit at: https://eidas.ec.europa.eu/EidasNode"

eidas-test-url:
	@[ -n "$(ORG)" ] || (echo "Usage: make eidas-test-url ORG=<org_slug>"; exit 1)
	@echo "SSO URL: $(CLAVEX_BASE)/$(ORG)/eidas/sso?login_session_id=<SESSION_ID>"
	@echo "CEF demo node: $(CEF_NODE_URL)"
	@echo "Demo citizens: https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eIDAS+eID+Profile"

# ── OIDC Conformance Suite ────────────────────────────────────────────────────
# Requires Docker and a running clavex instance (make dev).
# Linux only: uses host.docker.internal -> host via host-gateway.
# ── OIDC Conformance Suite ────────────────────────────────────────────────────
# The OIDF suite has no public Docker image — it is built from source.
#
# Workflow:
#   1. make conformance-build         # clone + build JAR via Docker (~10 min, once)
#   2. make dev                       # start clavex on :8080
#   3. make conformance-up            # start MongoDB + suite on https://localhost:8443
#   4. make conformance-setup         # seed test org + client into clavex
#   5. make conformance-create-plans  # create all test plans via the suite API
#   6. open https://localhost.emobix.co.uk:8443 and run each plan
#
#   Plans created by conformance-create-plans:
#     clavex-basic      — OIDC Basic OP    (code flow, client_secret_basic)
#     clavex-basic-post — OIDC Basic OP    (code flow, client_secret_post)
#     clavex-config     — OIDC Config OP   (discovery / provider metadata)
#     clavex-dynamic    — OIDC Dynamic OP  (RFC 7591 dynamic client registration)
#     clavex-form-post  — OIDC Form Post OP (response_mode=form_post)
#     clavex-hybrid     — OIDC Hybrid Flow  (response_type=code id_token)
#     clavex-par        — PAR standalone   (RFC 9126 pushed authorization requests)
#     clavex-device     — Device Grant     (RFC 8628 device authorization)
#     clavex-fapi       — FAPI 2.0 Baseline DPoP  (private_key_jwt + DPoP)
#     clavex-fapi-mtls  — FAPI 2.0 Baseline MTLS  (private_key_jwt + MTLS)
#     clavex-fapi-jarm  — FAPI 2.0 Message Signing (JARM, response_mode=jwt)
#     clavex-oid4vci-issuer — OID4VCI Final Issuer (sd_jwt_vc, authorization_code, wallet_initiated)
#     clavex-haip       — HAIP 1.0 (High Assurance Interop Profile, eIDAS 2.0)
#     clavex-oid4vp-verifier — OID4VP 1.0 Final Verifier (sd-jwt-vc + url_query)
#     Plan 11 (Token Introspection) is a local test spec — no suite plan created
#
# Notes:
#   - localhost.emobix.co.uk is a real DNS record → 127.0.0.1 (maintained by OIDF).
#     If offline, add to /etc/hosts:
#     echo "127.0.0.1 localhost.emobix.co.uk" | sudo tee -a /etc/hosts
#   - On Linux, host.docker.internal requires Docker ≥ 20.10 or:
#     echo "127.0.0.1 host.docker.internal" | sudo tee -a /etc/hosts

CONFORMANCE_DIR  := .conformance-suite
CONFORMANCE_REPO := https://gitlab.com/openid/conformance-suite.git

.PHONY: conformance-build conformance-up conformance-down conformance-setup conformance-create-plans conformance-delete-plans conformance-run-tests conformance-status conformance-logs conformance-clean

# Step 1: clone and build the JAR using the suite's own Docker builder (no Java needed)
conformance-build:
	@if [ ! -d "$(CONFORMANCE_DIR)" ]; then \
		echo "Cloning OIDF conformance suite…"; \
		git clone --depth=1 $(CONFORMANCE_REPO) $(CONFORMANCE_DIR); \
	fi
	@if [ ! -f "$(CONFORMANCE_DIR)/target/fapi-test-suite.jar" ]; then \
		echo "Building conformance suite JAR (first run ~10 min)…"; \
		cd $(CONFORMANCE_DIR) && MAVEN_CACHE=./m2 docker compose -f builder-compose.yml run builder; \
	else \
		echo "JAR already built — skipping (run 'make conformance-clean' to rebuild)"; \
	fi

# Step 3: start MongoDB + nginx + suite server
conformance-up:
	@[ -f "$(CONFORMANCE_DIR)/target/fapi-test-suite.jar" ] || \
		(echo "Run 'make conformance-build' first"; exit 1)
	@# Linux: host.docker.internal is not automatic — inject host-gateway mapping.
	@printf 'services:\n  mongodb:\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n  nginx:\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n  server:\n    extra_hosts:\n      - "host.docker.internal:host-gateway"\n' \
		> $(CONFORMANCE_DIR)/docker-compose.override.yml
	cd $(CONFORMANCE_DIR) && docker compose up -d
	@echo ""
	@echo "Suite available at https://localhost.emobix.co.uk:8443 (wait ~30s for startup)"
	@echo "Run: make conformance-setup   (requires postgres running — docker compose up postgres redis -d)"

conformance-down:
	-cd $(CONFORMANCE_DIR) && docker compose down

conformance-logs:
	cd $(CONFORMANCE_DIR) && docker compose logs -f server

# Remove clone entirely — next conformance-build will re-clone and rebuild
conformance-clean:
	rm -rf $(CONFORMANCE_DIR)

# Seed test org + client into a running clavex instance
conformance-setup:
	@bash conformance/setup.sh

# Create all test plans in the running suite (requires conformance-up + conformance-setup)
# Plans created: Basic OP, Basic OP (client_secret_post), Config OP, Dynamic OP
#
# Local suite:   make conformance-create-plans
# Online suite:  SUITE_URL=https://www.certification.openid.net SUITE_TOKEN=<token> make conformance-create-plans
conformance-create-plans:
	@bash conformance/create-plans.sh

# Delete ALL plans in the suite (useful to start fresh before re-creating).
# Local suite:   make conformance-delete-plans
# Online suite:  SUITE_URL=https://www.certification.openid.net SUITE_TOKEN=<token> make conformance-delete-plans
conformance-delete-plans:
	@bash conformance/delete-plans.sh

# Run all conformance tests automatically (requires conformance-up + conformance-create-plans)
# Playwright drives the clavex login form; no manual interaction needed.
#
# Pass extra args:
#   make conformance-run-tests ARGS="--plan clavex-basic --headful"
#   make conformance-run-tests ARGS="--list"
#   make conformance-run-tests ARGS="--rerun --timeout 180"
#
# Online suite (certification.openid.net) — generate the token in your profile UI:
#   make conformance-run-tests \
#     SUITE_URL=https://www.certification.openid.net \
#     ARGS="--suite-token <your-api-token>"
conformance-run-tests:
	@command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }
	@python3 -c "import playwright" 2>/dev/null || { \
		echo "Installing Python dependencies…"; \
		pip install -q -r conformance/requirements.txt; \
		playwright install chromium; \
	}
	@SUITE_URL_ARG=""; \
	if [ -n "$(SUITE_URL)" ]; then SUITE_URL_ARG="--suite-url $(SUITE_URL)"; fi; \
	python3 conformance/run-tests.py $$SUITE_URL_ARG $(ARGS)

# conformance-status: reads current plan results (no test execution), prints
# the summary table and updates CONFORMANCE.md.
#
#   make conformance-status \
#     SUITE_URL=https://www.certification.openid.net \
#     ARGS="--suite-token <your-api-token>"
conformance-status:
	@command -v python3 >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }
	@python3 -c "import requests" 2>/dev/null || pip install -q -r conformance/requirements.txt
	@SUITE_URL_ARG=""; \
	if [ -n "$(SUITE_URL)" ]; then SUITE_URL_ARG="--suite-url $(SUITE_URL)"; fi; \
	python3 conformance/run-tests.py $$SUITE_URL_ARG --status $(ARGS)

# ── Quality ───────────────────────────────────────────────────────────────────

test:
	$(GOTEST)

test-cover:
	go test ./... -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	}
	golangci-lint run ./...

# ── OpenAPI spec validation ────────────────────────────────────────────────────
# openapi-check: verifies every route in server.go is documented in openapi.json.
# Run in CI to block merges that add routes without updating the spec.
#
#   make openapi-check        — fails with a diff if any route is undocumented
#   make openapi-update       — scaffolds missing path stubs into openapi.json
#   make openapi-enrich       — fills placeholder (TODO) summaries/tags in-place
#
# Summaries/tags are derived from the Echo handler reference on each route
# (e.g. smtpH.Get → tag "SMTP", summary "Get"), so stubs are human-meaningful.
#
openapi-check:
	@echo "Checking OpenAPI spec coverage…"
	@go run ./tools/speccheck \
		-spec internal/handler/spec/openapi.json \
		-server internal/server/server.go

# Scaffold stubs for any routes missing from the spec (idempotent).
# After running, review summaries and add request/response schemas.
openapi-update:
	@go run ./tools/speccheck \
		-spec internal/handler/spec/openapi.json \
		-server internal/server/server.go \
		-update

# Rewrite any leftover "TODO" summaries/tags with values derived from the
# matching handler. Operations that already carry a real summary are untouched.
openapi-enrich:
	@go run ./tools/speccheck \
		-spec internal/handler/spec/openapi.json \
		-server internal/server/server.go \
		-enrich

# Derive requestBody schemas for write endpoints from the handler request
# structs (static analysis). Only fills operations without a hand-written body.
openapi-gen:
	@go run ./tools/specgen -spec internal/handler/spec/openapi.json

.PHONY: openapi-check openapi-update openapi-enrich openapi-gen

fmt:
	gofmt -w -s .
	goimports -w .

tidy:
	go mod tidy

clean:
	rm -rf bin/ coverage.out coverage.html
