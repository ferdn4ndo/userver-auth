# uServer Auth

[![Go version](https://img.shields.io/github/go-mod/go-version/ferdn4ndo/userver-auth)](https://github.com/ferdn4ndo/userver-auth/blob/main/go.mod)
[![Release](https://img.shields.io/github/v/release/ferdn4ndo/userver-auth)](https://github.com/ferdn4ndo/userver-auth/releases)
[![Docker image size](https://img.shields.io/docker/image-size/ferdn4ndo/userver-auth/latest)](https://hub.docker.com/r/ferdn4ndo/userver-auth)
[![Docker pulls](https://img.shields.io/docker/pulls/ferdn4ndo/userver-auth)](https://hub.docker.com/r/ferdn4ndo/userver-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/ferdn4ndo/userver-auth)](https://goreportcard.com/report/github.com/ferdn4ndo/userver-auth)
[![Unit tests](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_ut_e2e.yaml/badge.svg?branch=main)](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_ut_e2e.yaml)
[![Grype scan](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_grype_scan.yaml/badge.svg?branch=main)](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_grype_scan.yaml)
[![Gitleaks](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_code_leaks.yaml/badge.svg?branch=main)](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_code_leaks.yaml)
[![Code quality](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_code_quality.yaml/badge.svg?branch=main)](https://github.com/ferdn4ndo/userver-auth/actions/workflows/test_code_quality.yaml)
[![License: MIT](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://github.com/ferdn4ndo/userver-auth/blob/main/LICENSE)


JWT-based authentication microservice: **Go** (Gin, `sqlx`, golang-migrate), **PostgreSQL**, HS256 access/refresh tokens, bcrypt passwords. The HTTP API matches the earlier Python deployment so existing clients keep working.

Part of the [uServer](https://github.com/users/ferdn4ndo/projects/1) stack.

## Requirements

- **Docker** and **Docker Compose** v2 (enable **BuildKit** for image builds, e.g. `export DOCKER_BUILDKIT=1`)
- **PostgreSQL** reachable from the app (Compose stack or external)
- **Go** is optional on the host: use **`make go-test`** / **`make go-build`** — they **`docker build --target dev`** then **`docker run`** with the repo bind-mounted (same **`Dockerfile`** as production; **`docker-compose.yml`** only runs the app, same idea as a single-service project such as **flora-hive**).

## Project layout

| Path | Role |
|------|------|
| `cmd/` | `userver-auth` CLI: `app:serve`, `migrate:up`, `migrate:down` |
| `internal/` | HTTP routes, services, repositories |
| `lib/` | Config (`POSTGRES_*`, JWT, secrets), DB wrapper, logging |
| `migrations/*.sql` | golang-migrate SQL (idempotent `CREATE IF NOT EXISTS` for existing DBs) |
| `integration/` | API tests against Postgres (skipped when `POSTGRES_HOST` is unset) |
| `entrypoint.sh` | Optional `setup.sh`, then `app:serve` |
| `setup.sh` | Postgres role/DB provisioning (root user), then **`migrate:up`** |
| `docker-compose.yml` | `userver-auth` only (Go tooling via **`Makefile`** + Dockerfile **`dev`** stage) |
| `.github/workflows/` | CI: Go tests in container + Postgres, ShellCheck, Gitleaks, Grype (triggers on **`main`**) |

## Database migrations (Alembic → golang-migrate)

- New migrations live under `migrations/` as `NNNNNN_name.up.sql` / `.down.sql`.
- The baseline revision **`000001_initial_schema`** uses **`CREATE TABLE IF NOT EXISTS`** so databases already populated by **Alembic** keep working: running `migrate:up` creates **`schema_migrations`** and applies only what is missing. The old **`alembic_version`** table can remain until you remove it manually after cutover.
- Revoked JWTs are stored in **`blocklist_tokens`** (`blocked_at`). If you still have the legacy table **`blacklist_tokens`** / column **`blacklisted_at`**, run once on Postgres:

  ```sql
  ALTER TABLE blacklist_tokens RENAME TO blocklist_tokens;
  ALTER TABLE blocklist_tokens RENAME COLUMN blacklisted_at TO blocked_at;
  ALTER TABLE blocklist_tokens RENAME CONSTRAINT uq_blacklist_tokens_token TO uq_blocklist_tokens_token;
  ```

  (Skip any line that errors because the object was already renamed.)

## Run with Docker Compose

1. Copy `.env.template` → `.env` and set Postgres, `APP_SECRET_KEY`, `SYSTEM_CREATION_TOKEN`, etc.
2. Create the external network if you use nginx-proxy: `docker network create nginx-proxy`
3. **Build the Linux binary with Docker** (writes `./out/userver-auth` on the bind-mounted repo):

   ```sh
   make go-build
   ```

4. Start:

   ```sh
   docker compose up --build
   ```

`working_dir` is `/code` (repo mount). Defaults: `MIGRATE_BIN=./out/userver-auth`, `APP_BIN=./out/userver-auth`. The production image (no volume) uses `/app/main` and `/app/migrations`.

`SKIP_DB_SETUP=1` skips `setup.sh` (no migrations).

## Configuration (env)

| Variable | Purpose |
|----------|---------|
| `ENV_MODE` | `prod` → TLS `sslmode=require` on Postgres; else `disable` |
| `APP_PORT` / `PORT` | Listen port (default `5000`; legacy `FLASK_PORT` still read if set) |
| `POSTGRES_*` | App DB connection |
| `POSTGRES_MAX_OPEN_CONNS` | Optional cap on open DB connections (default `20`) |
| `POSTGRES_ROOT_*` | Superuser for `setup.sh` only |
| `APP_SECRET_KEY` / `JWT_SECRET_KEY` | JWT HMAC secret (legacy `FLASK_SECRET_KEY` still read if set) |
| `SYSTEM_CREATION_TOKEN` | `Authorization: Token …` for `POST /auth/system` |
| `JWT_EXP_DELTA_SECS` / `JWT_REFRESH_DELTA_SECS` | Token lifetimes |
| `BCRYPT_COST` | Optional; default `13` in prod, `4` otherwise |
| `SENTRY_DSN` | Optional Sentry |
| `TRUSTED_PROXY_CIDRS` | Comma-separated CIDRs for Gin `X-Forwarded-*` trust (default: loopback + RFC1918) |
| `CORS_DEBUG` | Set to `1` or `true` for verbose rs/cors logs (default off; avoids noise on `/healthz` without `Origin`) |
| `RATELIMIT_GLOBAL_PROD` | Comma-separated global caps when `ENV_MODE=prod` (default `1000-D`; [ulule/limiter](https://github.com/ulule/limiter) format) |
| `RATELIMIT_GLOBAL_DEV` | Same for non-prod (default `10000-D,100-H`) |
| `RATELIMIT_AUTH_SYSTEM` | `/auth` system create + token rotate (default `100-D`) |
| `RATELIMIT_AUTH_BURST` | register, login, refresh, logout, password change (default `1000-H`) |
| `RATELIMIT_AUTH_READ` | `GET /auth/me` and user lookup (default `10000-H`) |
| `RATELIMIT_STORAGE_URI` | Reserved for a shared limiter store (unused in-process memory store today) |
| `SKIP_DB_SETUP` | `1` to skip DB setup on start |

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness `{"status":"ok"}` |
| POST | `/auth/system` | Create system (`Authorization: Token <SYSTEM_CREATION_TOKEN>`) |
| POST | `/auth/register` | Register user |
| POST | `/auth/login` | Login |
| POST | `/auth/refresh` | Refresh tokens (`Authorization: Bearer <refresh>`) |
| GET | `/auth/me` | Current user |
| PATCH | `/auth/me/password` | Change password |
| GET | `/auth/systems/<system_name>/users/<username>` | Lookup user |
| PATCH | `/auth/systems/<system_name>/token` | Rotate system token |
| POST | `/auth/logout` | Blocklist access token (revoke) |

## Testing

```sh
# Unit + integration (integration skips without POSTGRES_HOST)
make go-test

# With Postgres: ensure POSTGRES_* reach the container (e.g. `.env` is passed when present).
# If the DB is another service on the same external network as compose, use:
#   make go-test-integration DOCKER_NETWORK=nginx-proxy
make go-test-integration
```

CI builds the **`Dockerfile`** **`dev`** stage and runs `go test ./...` in that image with a Postgres service.

## CI/CD and Docker Hub

On push/PR to `main`: Go tests (containerized toolchain), ShellCheck on `*.sh`, Gitleaks, Grype (SARIF upload; build not failed on findings).

Release workflows publish **`ferdn4ndo/userver-auth:<tag>`** and assets as before.

```sh
docker pull ferdn4ndo/userver-auth:latest
```

## CLI examples

```sh
./out/userver-auth migrate:up
./out/userver-auth app:serve
./out/userver-auth health:probe   # exits 0 if /healthz is OK (used by the container image)
```

Load `.env` automatically via `godotenv` when present.
