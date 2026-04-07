-- Idempotent baseline compatible with existing Alembic-created databases.
-- golang-migrate uses schema_migrations; Alembic's alembic_version may remain until you remove it manually.

CREATE TABLE IF NOT EXISTS users (
    uuid UUID PRIMARY KEY,
    system_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    registered_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX IF NOT EXISTS users_uuid_key ON users (uuid);

CREATE TABLE IF NOT EXISTS blocklist_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(500) NOT NULL,
    blocked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    CONSTRAINT uq_blocklist_tokens_token UNIQUE (token)
);

CREATE TABLE IF NOT EXISTS system (
    id SERIAL PRIMARY KEY,
    name VARCHAR(500) NOT NULL,
    token VARCHAR(500) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    CONSTRAINT uq_system_name UNIQUE (name),
    CONSTRAINT uq_system_token UNIQUE (token)
);
