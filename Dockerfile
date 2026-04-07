# Dev / Makefile: Go toolchain (bind-mount repo at /code). Release build continues below.
FROM golang:1.26-bookworm AS dev
WORKDIR /code
ENV GOTOOLCHAIN=local GOMODCACHE=/go/pkg/mod

# Compile release binary
FROM golang:1.26-bookworm AS builder

ARG BUILD_DATE=unknown
ARG BUILD_VERSION=unknown
ARG VCS_REF=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/main ./cmd

# Run
FROM alpine:3.23

ARG BUILD_DATE=unknown
ARG BUILD_VERSION=unknown
ARG VCS_REF=unknown

LABEL maintainer="Fernando Constantino <const.fernando@gmail.com>"
LABEL org.opencontainers.image.title="userver-auth"
LABEL org.opencontainers.image.description="JWT authentication microservice (Go / PostgreSQL)"
LABEL org.opencontainers.image.url="https://github.com/ferdn4ndo/userver-auth"
LABEL org.opencontainers.image.source="https://github.com/ferdn4ndo/userver-auth"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.revision="${VCS_REF}"

RUN apk add --no-cache ca-certificates bash postgresql-client \
    && addgroup -g 65532 app \
    && adduser -D -H -u 65532 -G app app

WORKDIR /app

COPY --from=builder /out/main /app/main
COPY --from=builder /src/migrations /app/migrations
COPY entrypoint.sh setup.sh colors.sh /app/

RUN chmod +x /app/entrypoint.sh /app/setup.sh /app/main \
    && chown -R app:app /app

USER app

ENV MIGRATE_BIN=/app/main
ENV APP_BIN=/app/main
ENV APP_PORT=5000

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/app/main", "health:probe"]

CMD ["/bin/bash", "/app/entrypoint.sh"]
