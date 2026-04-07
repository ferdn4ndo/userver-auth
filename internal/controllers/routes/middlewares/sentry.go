package middlewares

import (
	sentrygin "github.com/getsentry/sentry-go/gin"

	"userver-auth/lib"
)

// SentryMiddleware adds Sentry when SENTRY_DSN is set.
type SentryMiddleware struct {
	handler lib.RequestHandler
	logger  lib.Logger
	env     lib.Env
}

func NewSentryMiddleware(handler lib.RequestHandler, logger lib.Logger, env lib.Env) SentryMiddleware {
	return SentryMiddleware{handler: handler, logger: logger, env: env}
}

func (s SentryMiddleware) Setup() {
	if s.env.SentryDsn == "" {
		return
	}
	s.logger.Info("Setting up sentry middleware")
	s.handler.Gin.Use(sentrygin.New(sentrygin.Options{Repanic: true}))
}
