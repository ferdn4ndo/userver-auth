package middlewares

import (
	cors "github.com/rs/cors/wrapper/gin"

	"userver-auth/lib"
)

// CorsMiddleware attaches CORS to the Gin engine.
type CorsMiddleware struct {
	handler lib.RequestHandler
	logger  lib.Logger
	env     lib.Env
}

func NewCorsMiddleware(handler lib.RequestHandler, logger lib.Logger, env lib.Env) CorsMiddleware {
	return CorsMiddleware{handler: handler, logger: logger, env: env}
}

func (m CorsMiddleware) Setup() {
	m.logger.Info("Setting up cors middleware")
	m.handler.Gin.Use(cors.New(cors.Options{
		AllowCredentials: true,
		AllowOriginFunc:  func(string) bool { return true },
		AllowedHeaders:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"},
		// Verbose [cors] logs (e.g. "missing origin" on health checks) only when CORS_DEBUG=1.
		Debug: m.env.CorsDebug,
	}))
}
