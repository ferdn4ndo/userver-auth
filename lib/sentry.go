package lib

import (
	"github.com/getsentry/sentry-go"
)

// NewSentryHandler initializes Sentry when SENTRY_DSN is set.
func NewSentryHandler(logger Logger, env Env) {
	if env.SentryDsn == "" {
		return
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              env.SentryDsn,
		EnableTracing:    true,
		TracesSampleRate: 1.0,
	})
	if err != nil {
		logger.Error("sentry.Init failed: ", err)
	}
}
