# uServer Auth

JWT-based authentication microservice built with **Flask**, **SQLAlchemy**, **PostgreSQL**, and **Alembic**. It started from ideas in [flask-jwt-auth](https://github.com/realpython/flask-jwt-auth); background in this [Real Python article](https://realpython.com/blog/python/token-based-authentication-with-flask/).

Part of the [uServer](https://github.com/users/ferdn4ndo/projects/1) stack.

## Requirements

- **Docker** and **Docker Compose** v2 (plugin or standalone `docker compose`)
- A **PostgreSQL** instance reachable from the app container (same Compose stack or external host)
- Optional **Redis** (or compatible URL) for shared rate-limit storage when running more than one app replica (see `.env.template`)

## Project layout (high level)

| Path | Role |
|------|------|
| `entrypoint.sh` | Chooses config from `ENV_MODE`, runs DB setup, starts **Waitress** (`python -m waitress`) |
| `setup.sh` | Postgres role/databases + Alembic (`upgrade` or first-time `init` / `migrate`) |
| `colors.sh` | Shared ANSI colors (sourced by `entrypoint.sh` and `setup.sh`) |
| `manage.py` | Flask app for `FLASK_APP=manage:app` — CLI: `flask db …`, `flask test`, `flask run-prod`, etc. |
| `project/server/` | Flask app, config, auth blueprints, models |
| `migrations/` | Alembic (created by `setup.sh` / `flask db init`; committed after first migration) |
| `docker-compose.yml` | Builds and runs `userver-auth`, attaches external network `nginx-proxy` |
| `.github/workflows/` | CI: unit tests (Docker + Postgres), ShellCheck, Gitleaks, Grype scan; release workflows |

## CI/CD and Docker Hub

On **push** and **pull requests** to `main`, GitHub Actions builds the image, runs **`flask test`** against a Postgres service, runs ShellCheck on `*.sh`, Gitleaks, and a **Grype** scan whose SARIF is uploaded to the **Security** tab (the workflow does not fail the build on reported base-image CVEs; triage and rebuild images as upstream fixes land).

When you **publish a GitHub Release**, two workflows run (same pattern as the other `ferdn4ndo/*` images):

1. **`create_release_container.yaml`** — builds and pushes **`ferdn4ndo/userver-auth:<tag>`** and **`ferdn4ndo/userver-auth:latest`** to Docker Hub. Configure repository secrets **`DOCKER_LOGIN`** and **`DOCKER_PASSWORD`** (and ensure the Docker Hub repo exists or can be created).
2. **`create_release_assets.yaml`** — uploads a source tarball and `checksum.txt` to the release.

Pull the published image:

```sh
docker pull ferdn4ndo/userver-auth:latest
```

Run it with your own `.env` / `-e` flags and a reachable Postgres instance (the image includes the app; use your stack’s networking and secrets).

## Prepare the environment

1. Copy `.env.template` to `.env` and fill in values (Postgres, secrets, optional proxy/Let’s Encrypt vars).
2. Ensure the **external** Docker network named in `docker-compose.yml` exists (this repo expects `nginx-proxy`), or change/remove the `networks` block for local-only runs:

   ```sh
   docker network create nginx-proxy
   ```

3. **Commit Alembic revisions** under `migrations/` after you generate them (they are not gitignored so `flask db upgrade` works for other clones and CI).

## Run the application

```sh
docker compose up --build
```

On **every container start**, `entrypoint.sh` runs **`setup.sh`** (no `--reset`): it ensures the app Postgres user and databases exist, aligns DB ownership for PostgreSQL 15+, then runs **`flask db upgrade`** when `migrations/versions` has revisions, otherwise bootstraps Alembic. After that, **Waitress** serves `project.server:app` on `0.0.0.0:${FLASK_PORT:-5000}`.

To **skip** DB setup (e.g. Postgres temporarily unavailable, or migrations managed outside the container), set in `.env`:

```env
SKIP_DB_SETUP=1
```

The app will start without applying migrations; use only when you understand the trade-offs.

### Configuration

| Variable | Purpose |
|----------|---------|
| `ENV_MODE` | `prod` → `ProductionConfig`; unset or any other value → `DevelopmentConfig` |
| `APP_SETTINGS` | Normally set by entrypoint; override only if you know what you are doing |
| `FLASK_PORT` | Listen port inside the container (default `5000`) |
| `WAITRESS_THREADS` | Waitress thread pool (default `8`) |
| `RATELIMIT_STORAGE_URI` / `REDIS_URL` | Flask-Limiter backend; use Redis in multi-instance production |
| `FLASK_SECRET_KEY` | Flask session/signing; keep secret |
| `SYSTEM_CREATION_TOKEN` | Bearer token required to create systems (`Authorization: Token …`) |
| `JWT_EXP_DELTA_SECS` / `JWT_REFRESH_DELTA_SECS` | Access and refresh token lifetimes |
| `POSTGRES_*` | App database connection |
| `POSTGRES_ROOT_*` | Superuser used only by `setup.sh` for DDL |
| `SKIP_DB_SETUP` | Set to `1` to skip `setup.sh` on container start (see below) |

See `.env.template` for the full list and comments.

### Security notes

- Treat **`FLASK_SECRET_KEY`**, **`POSTGRES_PASS`**, **`POSTGRES_ROOT_PASS`**, and **`SYSTEM_CREATION_TOKEN`** as secrets; never commit real `.env` files.
- **`POSTGRES_ROOT_*`** is powerful: scope network access so only trusted hosts reach Postgres.
- Prefer **`RATELIMIT_STORAGE_URI`** pointing at **Redis** when you run **multiple** app containers so limits are shared.
- **`DEBUG`** is off in production config; keep `ENV_MODE=prod` in production.

### Performance notes

- Tune **`WAITRESS_THREADS`** for CPU and expected concurrency.
- Rate limits are configured in `project/server/config.py` (`THROTTLING_LIMITS`) per environment.

## Database setup (`setup.sh`)

`setup.sh` is invoked automatically from **`entrypoint.sh`** on each start. You can also run it manually:

**Idempotent run** (no drops): creates role/databases if missing, fixes owner when needed, then `flask db upgrade` or first-time migration bootstrap.

```sh
docker exec -it userver-auth bash -c "./setup.sh"
```

**Destructive reset** (drops app DBs and role, deletes `./migrations`, recreates schema + initial revision):

```sh
docker exec -it userver-auth bash -c "./setup.sh --reset"
```

**Help**

```sh
docker exec -it userver-auth bash -c "./setup.sh --help"
```

If **`ALTER DATABASE … OWNER`** fails, close other connections to that database and retry.

Use **`docker exec … sh -c`** only if the script is POSIX-clean; this project expects **bash** for `setup.sh` and `entrypoint.sh`.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/system` | Create a system (requires `Authorization: Token <SYSTEM_CREATION_TOKEN>`) |
| POST | `/auth/register` | Register a user in a system |
| POST | `/auth/login` | Login |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/auth/me` | Current user / token check |
| POST | `/auth/logout` | Logout (blacklist refresh token) |

Static docs may be served under the app’s configured static path when present.

## Testing

```sh
docker exec -it userver-auth bash -c "flask test"
docker exec -it userver-auth bash -c "flask cov"
```

`FLASK_APP=manage:app` is set in the image so `flask` commands work without extra `-e`.

## Flask CLI (manual)

Examples: `flask db current`, `flask run-prod` (Waitress via Flask), `flask create-db`. Prefer the image default of **`python -m waitress`** from `entrypoint.sh` for production-like logging.
