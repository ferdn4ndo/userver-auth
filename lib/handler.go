package lib

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// RequestHandler holds the Gin engine (routes use the same paths as the legacy HTTP API).
type RequestHandler struct {
	Gin *gin.Engine
}

// NewRequestHandler creates the HTTP engine.
func NewRequestHandler(logger Logger, env Env) RequestHandler {
	gin.DefaultWriter = logger.GetGinLogger()
	if !env.IsLocal() {
		gin.SetMode(gin.ReleaseMode)
	}
	engine := gin.New()
	gl := logger.GetGinLogger()
	engine.Use(gin.LoggerWithWriter(&gl), gin.Recovery())
	proxies := []string{"127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if cidr := strings.TrimSpace(env.TrustedProxyCIDRs); cidr != "" {
		parts := strings.Split(cidr, ",")
		proxies = proxies[:0]
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				proxies = append(proxies, t)
			}
		}
	}
	if len(proxies) == 0 {
		proxies = []string{"127.0.0.1", "::1"}
	}
	if err := engine.SetTrustedProxies(proxies); err != nil {
		logger.Error("SetTrustedProxies: ", err.Error())
	}
	return RequestHandler{Gin: engine}
}
