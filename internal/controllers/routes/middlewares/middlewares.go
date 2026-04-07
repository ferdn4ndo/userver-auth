package middlewares

import "go.uber.org/fx"

// Module registers HTTP middleware applied in order.
var Module = fx.Options(
	fx.Provide(NewSecurityHeadersMiddleware),
	fx.Provide(NewSentryMiddleware),
	fx.Provide(NewCorsMiddleware),
	fx.Provide(NewMiddlewares),
)

// IMiddleware runs Setup on the Gin engine.
type IMiddleware interface {
	Setup()
}

// Middlewares is an ordered list of middleware.
type Middlewares []IMiddleware

func NewMiddlewares(security SecurityHeadersMiddleware, sentry SentryMiddleware, cors CorsMiddleware) Middlewares {
	return Middlewares{security, sentry, cors}
}

func (m Middlewares) Setup() {
	for _, mw := range m {
		mw.Setup()
	}
}
