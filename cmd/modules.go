package main

import (
	"go.uber.org/fx"

	"userver-auth/internal/controllers/routes"
	"userver-auth/internal/infrastructure"
	"userver-auth/internal/services"
	"userver-auth/lib"
)

// CommonModules is the full application graph.
var CommonModules = fx.Options(
	lib.Module,
	routes.Module,
	services.Module,
	infrastructure.Module,
)
