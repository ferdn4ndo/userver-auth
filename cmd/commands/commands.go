package commands

import (
	"context"
	"net/http"

	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"userver-auth/lib"
)

func Commands(opt fx.Option) []*cobra.Command {
	return []*cobra.Command{
		WrapServerCommand("app:serve", NewServeCommand(), opt),
		WrapSubCommand("migrate:up", NewMigrateUpCommand(), opt),
		WrapSubCommand("migrate:down", NewMigrateDownCommand(), opt),
	}
}

func WrapSubCommand(name string, cmd lib.Command, opt fx.Option) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: cmd.Short(),
		Run: func(c *cobra.Command, args []string) {
			logger := lib.GetLogger()
			opts := fx.Options(
				fx.WithLogger(func() fxevent.Logger {
					return logger.GetFxLogger()
				}),
				fx.Invoke(cmd.Run()),
			)
			ctx := context.Background()
			app := fx.New(opt, opts)
			if err := app.Start(ctx); err != nil {
				logger.Fatal(err)
			}
			defer func() {
				if err := app.Stop(ctx); err != nil {
					logger.Error("Could not gracefully stop application: ", err)
				}
			}()
		},
	}
}

func WrapServerCommand(name string, cmd lib.Command, opt fx.Option) *cobra.Command {
	return &cobra.Command{
		Use:   name,
		Short: cmd.Short(),
		Run: func(c *cobra.Command, args []string) {
			logger := lib.GetLogger()
			opts := fx.Options(
				opt,
				fx.WithLogger(func() fxevent.Logger {
					return logger.GetFxLogger()
				}),
				fx.Provide(cmd.Run()),
				fx.Invoke(func(*http.Server) {}),
			)
			fx.New(opts).Run()
		},
	}
}
