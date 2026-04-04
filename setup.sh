#!/bin/bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./colors.sh

usage() {
  echo "Usage: $0 [--reset]"
  echo "  (default) Ensure Postgres role and databases exist, then apply migrations."
  echo "  --reset   Drop app databases and role, remove ./migrations, then recreate everything."
  exit "${1:-0}"
}

RESET=false
for arg in "$@"; do
  case "$arg" in
    --reset) RESET=true ;;
    -h|--help) usage 0 ;;
    *)
      echo "Unknown option: $arg" >&2
      usage 1
      ;;
  esac
done

# PostgreSQL 15+: app user should own the databases so schema public allows DDL (pg_database_owner).
# Escape single quotes in password for SQL string literals ('' per SQL standard).
sql_escape_literal() {
  printf '%s' "${1//\'/\'\'}"
}

POSTGRES_PASS_ESC=$(sql_escape_literal "${POSTGRES_PASS}")

# PostgreSQL 15+ no longer grants CREATE on schema public to everyone. GRANT ALL ON DATABASE
# only covers database-level rights (e.g. CONNECT), not DDL in public. Making the app user
# the database owner aligns public schema ownership (via pg_database_owner) so migrations work.

if [ "$RESET" = true ]; then
  echo -e "${COLOR_YELLOW}Reset: dropping app databases and role...${COLOR_RESET}"
  PGPASSWORD=${POSTGRES_ROOT_PASS} psql -h "${POSTGRES_HOST}" -U "${POSTGRES_ROOT_USER}" -p "${POSTGRES_PORT}" -v ON_ERROR_STOP=1 <<EOF
DROP DATABASE IF EXISTS ${POSTGRES_DB};
DROP DATABASE IF EXISTS ${POSTGRES_DB_TEST};

DO \$do\$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${POSTGRES_USER}') THEN
    EXECUTE format('DROP OWNED BY %I CASCADE', '${POSTGRES_USER}');
    EXECUTE format('DROP ROLE %I', '${POSTGRES_USER}');
  END IF;
END
\$do\$;

CREATE USER ${POSTGRES_USER} WITH ENCRYPTED PASSWORD '${POSTGRES_PASS_ESC}';

CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};
CREATE DATABASE ${POSTGRES_DB_TEST} OWNER ${POSTGRES_USER};

REVOKE ALL PRIVILEGES ON DATABASE postgres FROM ${POSTGRES_USER};
EOF
  rm -rf migrations
else
  echo -e "${COLOR_BLUE}Ensuring Postgres role and databases exist (no drop; use --reset to recreate)...${COLOR_RESET}"
  # Dollar-quote tags avoid shell/SQL issues with quotes or % in the password (format %L would mangle %).
  TAGU="_u${RANDOM}${RANDOM}_$$_"
  TAGP="_p${RANDOM}${RANDOM}_$$_"
  PGPASSWORD=${POSTGRES_ROOT_PASS} psql -h "${POSTGRES_HOST}" -U "${POSTGRES_ROOT_USER}" -p "${POSTGRES_PORT}" -v ON_ERROR_STOP=1 <<EOF
DO \$do\$
DECLARE
  un text := \$${TAGU}\$${POSTGRES_USER}\$${TAGU}\$;
  pw text := \$${TAGP}\$${POSTGRES_PASS}\$${TAGP}\$;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = un) THEN
    EXECUTE 'CREATE ROLE ' || quote_ident(un) || ' LOGIN PASSWORD ' || quote_literal(pw);
  ELSE
    -- Volume / older deploy: role exists but password may not match POSTGRES_PASS anymore.
    EXECUTE 'ALTER ROLE ' || quote_ident(un) || ' WITH LOGIN PASSWORD ' || quote_literal(pw);
  END IF;
END
\$do\$;

DO \$do\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = '${POSTGRES_DB}') THEN
    EXECUTE format('CREATE DATABASE %I OWNER %I', '${POSTGRES_DB}', '${POSTGRES_USER}');
  ELSIF EXISTS (
    SELECT 1 FROM pg_catalog.pg_database d
    JOIN pg_catalog.pg_roles r ON r.oid = d.datdba
    WHERE d.datname = '${POSTGRES_DB}' AND r.rolname IS DISTINCT FROM '${POSTGRES_USER}'
  ) THEN
    EXECUTE format('ALTER DATABASE %I OWNER TO %I', '${POSTGRES_DB}', '${POSTGRES_USER}');
  END IF;
END
\$do\$;

DO \$do\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = '${POSTGRES_DB_TEST}') THEN
    EXECUTE format('CREATE DATABASE %I OWNER %I', '${POSTGRES_DB_TEST}', '${POSTGRES_USER}');
  ELSIF EXISTS (
    SELECT 1 FROM pg_catalog.pg_database d
    JOIN pg_catalog.pg_roles r ON r.oid = d.datdba
    WHERE d.datname = '${POSTGRES_DB_TEST}' AND r.rolname IS DISTINCT FROM '${POSTGRES_USER}'
  ) THEN
    EXECUTE format('ALTER DATABASE %I OWNER TO %I', '${POSTGRES_DB_TEST}', '${POSTGRES_USER}');
  END IF;
END
\$do\$;

REVOKE ALL PRIVILEGES ON DATABASE postgres FROM ${POSTGRES_USER};
EOF
fi

export FLASK_APP=manage:app

if [ "$RESET" = true ]; then
  echo -e "${COLOR_BLUE}Creating tables and initial migration...${COLOR_RESET}"
  flask create-db
  flask db init
  flask db migrate
else
  if [ -d migrations/versions ] && [ -n "$(ls -A migrations/versions 2>/dev/null)" ]; then
    echo -e "${COLOR_BLUE}Applying Alembic migrations...${COLOR_RESET}"
    flask db upgrade
    # create_all only adds tables missing from the DB (safe with Alembic). Covers bind-mounted
    # trees that omit a revision file, or DBs that never got the system-table migration.
    echo -e "${COLOR_BLUE}Ensuring model tables exist (CREATE missing only)...${COLOR_RESET}"
    flask create-db
  else
    echo -e "${COLOR_BLUE}No migrations yet: creating tables and initializing Alembic...${COLOR_RESET}"
    flask create-db
    flask db init
    flask db migrate
  fi
fi

echo -e "${COLOR_GREEN}Done!${COLOR_RESET}"
