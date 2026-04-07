package routes

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/fx"

	"userver-auth/internal/controllers/routes/middlewares"
	"userver-auth/lib"
)

// Module exports route wiring.
var Module = fx.Options(
	fx.Provide(NewHealthRoutes),
	fx.Provide(NewAuthRoutes),
	fx.Provide(NewRoutes),
	middlewares.Module,
)

// Routes applies global middleware and registers HTTP handlers.
type Routes struct {
	handler   lib.RequestHandler
	mw        middlewares.Middlewares
	health    HealthRoutes
	auth      AuthRoutes
	defaultRL gin.HandlerFunc
	logger    lib.Logger
}

// NewRoutes builds route setup; fails if default rate limiter cannot be configured.
func NewRoutes(
	handler lib.RequestHandler,
	mw middlewares.Middlewares,
	health HealthRoutes,
	auth AuthRoutes,
	env lib.Env,
	logger lib.Logger,
) (Routes, error) {
	rl, err := DefaultRateLimit(env)
	if err != nil {
		return Routes{}, err
	}
	return Routes{
		handler:   handler,
		mw:        mw,
		health:    health,
		auth:      auth,
		defaultRL: rl,
		logger:    logger,
	}, nil
}

// Setup registers middleware and routes on the Gin engine.
func (r Routes) Setup() {
	r.logger.Info("Setting up HTTP routes")
	r.handler.Gin.Use(r.defaultRL)
	r.mw.Setup()
	r.health.Setup()
	r.auth.Setup()
}
