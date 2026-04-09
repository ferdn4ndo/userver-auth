package repositories

import (
	"go.uber.org/fx"

	"userver-auth/internal/services"
)

// Module wires data access constructors. fx.As exposes the same instances as services.*Store interfaces for DI.
var Module = fx.Options(
	fx.Provide(
		fx.Annotate(
			NewSystemRepository,
			fx.As(new(services.SystemStore)),
		),
	),
	fx.Provide(
		fx.Annotate(
			NewUserRepository,
			fx.As(new(services.UserStore)),
		),
	),
	fx.Provide(
		fx.Annotate(
			NewBlocklistRepository,
			fx.As(new(services.BlocklistStore)),
		),
	),
)
