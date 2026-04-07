# Go commands use the Dockerfile dev stage + docker run (no extra Compose service).
# Same pattern as a single-service compose app: one image definition in the Dockerfile.
# Requires Docker + BuildKit (DOCKER_BUILDKIT=1).

DEV_IMAGE ?= userver-auth:dev
GO_MOD_CACHE_VOL ?= userver-auth-go-mod
GO_VOLUMES := -v "$(CURDIR):/code" -w /code -v $(GO_MOD_CACHE_VOL):/go/pkg/mod
GO_ENV := -e GOTOOLCHAIN=local -e GOMODCACHE=/go/pkg/mod -e CGO_ENABLED=0
# Optional: join the same external network as docker-compose.yml (e.g. nginx-proxy) for Postgres by service name.
DOCKER_NETWORK ?=
ifneq ($(strip $(DOCKER_NETWORK)),)
GO_DOCKER_NET := --network $(DOCKER_NETWORK)
else
GO_DOCKER_NET :=
endif
ifneq ($(wildcard $(CURDIR)/.env),)
GO_DOTENV := --env-file $(CURDIR)/.env
else
GO_DOTENV :=
endif

.PHONY: dev-image go-help go-version go-mod-download go-mod-tidy go-test go-test-integration go-test-race go-vet go-fmt go-build go-shell

dev-image:
	DOCKER_BUILDKIT=1 docker build --target dev -t $(DEV_IMAGE) .

go-help:
	@echo "Go targets: build dev image (Dockerfile target dev), then docker run."
	@echo "  make dev-image go-version go-mod-tidy go-test go-vet go-fmt go-build go-shell"

go-version: dev-image
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go version

go-mod-download: dev-image
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go mod download

go-mod-tidy: dev-image
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go mod tidy

go-test: dev-image
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go test ./...

# Integration tests need POSTGRES_* (e.g. via .env or -e). Use DOCKER_NETWORK=nginx-proxy if Postgres is on that Compose network.
go-test-integration: dev-image
	docker run --rm $(GO_DOCKER_NET) $(GO_DOTENV) $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go test ./... -count=1 -v

go-test-race: dev-image
	docker run --rm $(GO_VOLUMES) \
		-e GOTOOLCHAIN=local -e GOMODCACHE=/go/pkg/mod -e CGO_ENABLED=1 \
		$(DEV_IMAGE) go test -race ./...

go-vet: dev-image
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go vet ./...

go-fmt: dev-image
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go fmt ./...

go-build: dev-image
	@mkdir -p out
	docker run --rm $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) go build -o /code/out/userver-auth ./cmd

go-shell: dev-image
	docker run --rm -it $(GO_VOLUMES) $(GO_ENV) $(DEV_IMAGE) bash
