package commands

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"

	"userver-auth/lib"
)

type MigrateUpCommand struct{}

func (s *MigrateUpCommand) Short() string { return "migrate up the database" }
func (s *MigrateUpCommand) Setup(cmd *cobra.Command) {}

func (s *MigrateUpCommand) Run() lib.CommandRunner {
	return func(logger lib.Logger, database lib.Database) {
		logger.Info("Starting migration up run")
		m := createMigrationStruct(database, logger)
		err := m.Up()
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			logger.Fatal(fmt.Errorf("migrate up: %w", err))
		}
		logger.Info("Migration up was successful")
	}
}

func NewMigrateUpCommand() *MigrateUpCommand { return &MigrateUpCommand{} }

type MigrateDownCommand struct{}

func (s *MigrateDownCommand) Short() string { return "migrate down the database" }
func (s *MigrateDownCommand) Setup(cmd *cobra.Command) {}

func (s *MigrateDownCommand) Run() lib.CommandRunner {
	return func(logger lib.Logger, database lib.Database) {
		logger.Info("Starting migration down run")
		m := createMigrationStruct(database, logger)
		err := m.Down()
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			logger.Fatal(fmt.Errorf("migrate down: %w", err))
		}
		logger.Info("Migration down was successful")
	}
}

func NewMigrateDownCommand() *MigrateDownCommand { return &MigrateDownCommand{} }

func createMigrationStruct(database lib.Database, logger lib.Logger) *migrate.Migrate {
	driver, err := postgres.WithInstance(database.StdDB(), &postgres.Config{})
	if err != nil {
		logger.Fatal(fmt.Errorf("postgres migrate driver: %w", err))
	}
	m, err := migrate.NewWithDatabaseInstance("file://migrations", "postgres", driver)
	if err != nil {
		logger.Fatal(fmt.Errorf("migrate instance: %w", err))
	}
	return m
}
