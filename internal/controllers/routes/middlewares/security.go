package middlewares

import (
	"github.com/gin-gonic/gin"

	"userver-auth/lib"
)

// SecurityHeadersMiddleware sets baseline HTTP response headers for JSON APIs.
type SecurityHeadersMiddleware struct {
	handler lib.RequestHandler
}

func NewSecurityHeadersMiddleware(handler lib.RequestHandler) SecurityHeadersMiddleware {
	return SecurityHeadersMiddleware{handler: handler}
}

func (m SecurityHeadersMiddleware) Setup() {
	m.handler.Gin.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	})
}
