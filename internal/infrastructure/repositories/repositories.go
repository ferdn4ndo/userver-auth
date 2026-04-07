package repositories

import "go.uber.org/fx"

// Module wires data access constructors.
var Module = fx.Options(
	fx.Provide(NewSystemRepository),
	fx.Provide(NewUserRepository),
	fx.Provide(NewBlocklistRepository),
)
