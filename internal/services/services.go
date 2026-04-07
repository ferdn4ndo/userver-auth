package services

import "go.uber.org/fx"

// Module wires application services.
var Module = fx.Options(
	fx.Provide(NewTokenService),
	fx.Provide(NewAuthService),
	fx.Provide(NewHealthService),
)
