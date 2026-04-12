package routes

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"userver-auth/lib"
)

var sharedMemStore = memory.NewStore()

// splitRateFormats parses a comma-separated list of ulule formatted rates (e.g. "1000-D,60-M").
func splitRateFormats(csv string) []string {
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func globalFormatsFromEnv(env lib.Env) []string {
	var csv string
	if env.IsProduction() {
		csv = env.RatelimitGlobalProd
	} else {
		csv = env.RatelimitGlobalDev
	}
	formats := splitRateFormats(csv)
	if len(formats) == 0 {
		if env.IsProduction() {
			return []string{"1000-D"}
		}
		return []string{"10000-D", "100-H"}
	}
	return formats
}

func composeLimiters(formats []string) ([]*limiter.Limiter, error) {
	out := make([]*limiter.Limiter, 0, len(formats))
	for _, f := range formats {
		rate, err := limiter.NewRateFromFormatted(f)
		if err != nil {
			return nil, err
		}
		out = append(out, limiter.New(sharedMemStore, rate))
	}
	return out, nil
}

// DefaultRateLimit applies global request caps (all routes except healthz).
// Formats come from RATELIMIT_GLOBAL_PROD or RATELIMIT_GLOBAL_DEV (comma-separated).
func DefaultRateLimit(env lib.Env) (gin.HandlerFunc, error) {
	formats := globalFormatsFromEnv(env)
	lim, err := composeLimiters(formats)
	if err != nil {
		return nil, err
	}
	return func(c *gin.Context) {
		if shouldSkipRateLimit(c) {
			c.Next()
			return
		}
		key := c.ClientIP() + "|" + c.Request.Method + "|" + c.FullPath()
		for _, l := range lim {
			ctx, err := l.Get(context.Background(), key)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			if ctx.Reached {
				c.AbortWithStatusJSON(420, gin.H{
					"message": fmt.Sprintf("Ratelimit exceeded: %s. Please, calm down!", strconv.FormatInt(ctx.Limit, 10)),
				})
				return
			}
		}
		c.Next()
	}, nil
}

// ExtraRateLimit adds route-specific limits on top of defaults.
func ExtraRateLimit(formatted string) (gin.HandlerFunc, error) {
	lim, err := composeLimiters([]string{formatted})
	if err != nil {
		return nil, err
	}
	l := lim[0]
	return func(c *gin.Context) {
		if shouldSkipRateLimit(c) {
			c.Next()
			return
		}
		key := c.ClientIP() + "|" + c.Request.Method + "|" + c.FullPath()
		ctx, err := l.Get(context.Background(), key)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if ctx.Reached {
			c.AbortWithStatusJSON(420, gin.H{
				"message": fmt.Sprintf("Ratelimit exceeded: %s. Please, calm down!", strconv.FormatInt(ctx.Limit, 10)),
			})
			return
		}
		c.Next()
	}, nil
}

func shouldSkipRateLimit(c *gin.Context) bool {
	p := c.Request.URL.Path
	return p == "/healthz" || p == "/" || p == "/favicon.ico"
}
