package services

import "go.uber.org/fx"

// Module wires application services.
var Module = fx.Options(
	fx.Provide(
		fx.Annotate(
			NewTokenService,
			fx.As(new(TokenIssuer)),
		),
	),
	fx.Provide(NewAuthService),
	fx.Provide(NewHealthService),
)
