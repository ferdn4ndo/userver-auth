package integration

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"

	"userver-auth/internal/controllers/routes"
	"userver-auth/internal/controllers/routes/middlewares"
	"userver-auth/internal/infrastructure/repositories"
	"userver-auth/internal/services"
	"userver-auth/lib"
)

var (
	routerOnce   sync.Once
	sharedEngine *gin.Engine
	sharedDB     *sqlx.DB
	setupErr     error
)

// Engine returns a shared Gin engine with a migrated database. Skips if POSTGRES_HOST is unset.
func Engine(t *testing.T) *gin.Engine {
	t.Helper()
	if os.Getenv("POSTGRES_HOST") == "" {
		t.Skip("integration tests require POSTGRES_HOST")
	}
	routerOnce.Do(func() { setupErr = doSetup() })
	require.NoError(t, setupErr)
	return sharedEngine
}

// ResetDB truncates application tables between tests.
func ResetDB(t *testing.T) {
	t.Helper()
	_, err := sharedDB.Exec(`TRUNCATE blocklist_tokens, users, system RESTART IDENTITY CASCADE`)
	require.NoError(t, err)
}

func migrationsDirURL() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	return "file://" + filepath.Join(repoRoot, "migrations")
}

func testDSN() string {
	u := url.UserPassword(os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASS"))
	db := os.Getenv("POSTGRES_DB")
	if db == "" {
		db = "userver_auth_test_ci"
	}
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"
	}
	return fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=disable",
		u.String(), host, port, db)
}

func doSetup() error {
	_ = os.Setenv("ENV_MODE", "development")
	if os.Getenv("APP_SECRET_KEY") == "" && os.Getenv("JWT_SECRET_KEY") == "" && os.Getenv("FLASK_SECRET_KEY") == "" {
		_ = os.Setenv("APP_SECRET_KEY", "ci-app-secret-not-for-production-min-32-chars!!")
	}
	if os.Getenv("SYSTEM_CREATION_TOKEN") == "" {
		_ = os.Setenv("SYSTEM_CREATION_TOKEN", "ci-system-creation-token")
	}
	if os.Getenv("JWT_EXP_DELTA_SECS") == "" {
		_ = os.Setenv("JWT_EXP_DELTA_SECS", "3600")
	}
	if os.Getenv("JWT_REFRESH_DELTA_SECS") == "" {
		_ = os.Setenv("JWT_REFRESH_DELTA_SECS", "259200")
	}
	_ = os.Setenv("BCRYPT_COST", "4")
	_ = os.Setenv("APP_PORT", "5000")

	migSQL, err := sql.Open("postgres", testDSN())
	if err != nil {
		return err
	}
	if err := migSQL.Ping(); err != nil {
		_ = migSQL.Close()
		return err
	}
	d, err := postgres.WithInstance(migSQL, &postgres.Config{})
	if err != nil {
		_ = migSQL.Close()
		return err
	}
	m, err := migrate.NewWithDatabaseInstance(migrationsDirURL(), "postgres", d)
	if err != nil {
		_ = migSQL.Close()
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		_, _ = m.Close()
		_ = migSQL.Close()
		return err
	}
	_, _ = m.Close()
	_ = migSQL.Close()

	db, err := sqlx.Open("postgres", testDSN())
	if err != nil {
		return err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return err
	}
	sharedDB = db

	if _, err := db.Exec(`TRUNCATE blocklist_tokens, users, system RESTART IDENTITY CASCADE`); err != nil {
		return err
	}

	env := lib.NewEnv()
	logger := lib.GetLogger()
	database := lib.Database{DB: db}

	sysR := repositories.NewSystemRepository(database)
	userR := repositories.NewUserRepository(database)
	blR := repositories.NewBlocklistRepository(database)
	tok := services.NewTokenService(env, blR)
	auth := services.NewAuthService(env, sysR, userR, blR, tok)
	health := services.NewHealthService()

	gin.SetMode(gin.TestMode)
	h := lib.NewRequestHandler(logger, env)
	rl, err := routes.DefaultRateLimit(env)
	if err != nil {
		return err
	}
	h.Gin.Use(rl)
	middlewares.NewSentryMiddleware(h, logger, env).Setup()
	middlewares.NewCorsMiddleware(h, logger, env).Setup()
	routes.NewHealthRoutes(h, health, logger).Setup()
	if err := routes.NewAuthRoutes(h, env, auth, logger).Setup(); err != nil {
		return err
	}

	sharedEngine = h.Gin
	return nil
}
