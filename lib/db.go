package lib

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"go.uber.org/fx"
)

// QueryAble matches sqlx operations used by repositories.
type QueryAble interface {
	sqlx.Ext
	NamedExec(query string, arg interface{}) (sql.Result, error)
	NamedQuery(query string, arg interface{}) (*sqlx.Rows, error)
	Select(dest interface{}, query string, args ...interface{}) error
	Get(dest interface{}, query string, args ...interface{}) error
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// Database wraps sqlx.DB.
type Database struct {
	*sqlx.DB
}

// StdDB returns the underlying *sql.DB (e.g. for golang-migrate).
func (d Database) StdDB() *sql.DB {
	return d.DB.DB
}

// NewDatabase opens PostgreSQL using POSTGRES_* env vars.
func NewDatabase(env Env, logger Logger, lc fx.Lifecycle) Database {
	u := url.UserPassword(env.DBUser, env.DBPassword)
	sslMode := "disable"
	if env.IsProduction() {
		sslMode = "require"
	}
	q := url.Values{}
	q.Set("sslmode", sslMode)
	q.Set("application_name", "userver-auth")
	dsn := fmt.Sprintf("postgres://%s@%s:%s/%s?%s",
		u.String(), env.DBHost, env.DBPort, env.DBName, q.Encode())

	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		logger.Panic(err)
		panic(err.Error())
	}
	maxOpen := 20
	if v := os.Getenv("POSTGRES_MAX_OPEN_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxOpen = n
		}
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetConnMaxIdleTime(10 * time.Second)
	db.SetMaxIdleConns(min(8, maxOpen))
	db.SetConnMaxLifetime(55 * time.Minute)

	lc.Append(fx.StopHook(func(ctx context.Context) error {
		return db.Close()
	}))

	logger.Info("Database connection established")

	return Database{DB: db}
}
