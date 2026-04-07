package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"userver-auth/internal/services"
	"userver-auth/lib"
)

// HealthRoutes registers liveness checks.
type HealthRoutes struct {
	handler *gin.Engine
	health  *services.HealthService
	logger  lib.Logger
}

func NewHealthRoutes(handler lib.RequestHandler, health *services.HealthService, logger lib.Logger) HealthRoutes {
	return HealthRoutes{handler: handler.Gin, health: health, logger: logger}
}

func (h HealthRoutes) Setup() {
	h.logger.Info("Setting up health routes")
	h.handler.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, h.health.Status())
	})
	h.handler.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	h.handler.GET("/favicon.ico", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
}
