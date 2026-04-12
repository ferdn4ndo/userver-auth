package commands

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"userver-auth/internal/controllers/routes"
	"userver-auth/lib"
)

type ServeCommand struct{}

func (s *ServeCommand) Short() string { return "serve application" }
func (s *ServeCommand) Setup(cmd *cobra.Command) {}

func (s *ServeCommand) Run() lib.CommandRunner {
	return func(
		env lib.Env,
		router lib.RequestHandler,
		route routes.Routes,
		logger lib.Logger,
		lc fx.Lifecycle,
	) *http.Server {
		server := &http.Server{
			Addr:              ":" + env.ServerPort,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
			Handler:           router.Gin,
		}
		lc.Append(fx.Hook{
			OnStart: func(ctx context.Context) error {
				lib.NewSentryHandler(logger, env)
				// Middleware is applied inside route.Setup() only (avoid double registration).
				if err := route.Setup(); err != nil {
					return fmt.Errorf("routes: %w", err)
				}
				ln, err := net.Listen("tcp", server.Addr)
				if err != nil {
					return fmt.Errorf("listen on %s: %w", server.Addr, err)
				}
				go func() {
					logger.Info("Running server on " + ln.Addr().String())
					if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
						logger.Error("Server error: ", err.Error())
					}
				}()
				return nil
			},
			OnStop: func(ctx context.Context) error {
				return server.Shutdown(ctx)
			},
		})
		return server
	}
}

func NewServeCommand() *ServeCommand { return &ServeCommand{} }
