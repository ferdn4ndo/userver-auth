package routes

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"userver-auth/lib"
)

var sharedMemStore = memory.NewStore()

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
func DefaultRateLimit(env lib.Env) (gin.HandlerFunc, error) {
	var formats []string
	if env.IsProduction() {
		formats = []string{"1000-D", "10-M"}
	} else {
		formats = []string{"10000-D", "100-H"}
	}
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
