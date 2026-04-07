package lib

import (
	"os"
	"strconv"
	"strings"
)

// Env holds configuration loaded from the process environment.
type Env struct {
	ServerPort string
	EnvMode    string
	LogLevel   string

	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	AppSecretKey        string
	SystemCreationToken string
	JWTExpDeltaSecs     int
	JWTRefreshDeltaSecs int
	BcryptCost          int
	RateLimitStorageURI string
	RedisURL            string
	SentryDsn           string
	// TrustedProxyCIDRs is a comma-separated list for Gin SetTrustedProxies (empty = loopback + RFC1918).
	TrustedProxyCIDRs string
	// CorsDebug enables verbose rs/cors logs (default off; set CORS_DEBUG=1 to troubleshoot).
	CorsDebug bool
}

// IsLocal is true when not running in production mode.
func (e Env) IsLocal() bool {
	return !e.IsProduction()
}

// IsProduction mirrors ENV_MODE=prod used by entrypoint.sh.
func (e Env) IsProduction() bool {
	return strings.EqualFold(strings.TrimSpace(e.EnvMode), "prod")
}

// NewEnv loads environment variables (no config file required for Docker/CI).
func NewEnv() Env {
	jwtExp, _ := strconv.Atoi(getenvDefault("JWT_EXP_DELTA_SECS", "3600"))
	jwtRef, _ := strconv.Atoi(getenvDefault("JWT_REFRESH_DELTA_SECS", "259200"))
	bcryptCost, _ := strconv.Atoi(getenvDefault("BCRYPT_COST", ""))
	if bcryptCost <= 0 {
		if getenvDefault("ENV_MODE", "") == "prod" {
			bcryptCost = 13
		} else {
			bcryptCost = 4
		}
	}

	port := getenvFirstNonEmpty([]string{"APP_PORT", "PORT", "FLASK_PORT"}, "5000")
	secret := getenvFirstNonEmpty([]string{"APP_SECRET_KEY", "JWT_SECRET_KEY", "FLASK_SECRET_KEY"}, "")

	return Env{
		ServerPort:          port,
		EnvMode:             getenvDefault("ENV_MODE", "development"),
		LogLevel:            getenvDefault("LOG_LEVEL", "info"),
		DBHost:              os.Getenv("POSTGRES_HOST"),
		DBPort:              getenvDefault("POSTGRES_PORT", "5432"),
		DBUser:              os.Getenv("POSTGRES_USER"),
		DBPassword:          os.Getenv("POSTGRES_PASS"),
		DBName:              os.Getenv("POSTGRES_DB"),
		AppSecretKey:        secret,
		SystemCreationToken: os.Getenv("SYSTEM_CREATION_TOKEN"),
		JWTExpDeltaSecs:     jwtExp,
		JWTRefreshDeltaSecs: jwtRef,
		BcryptCost:          bcryptCost,
		RateLimitStorageURI: os.Getenv("RATELIMIT_STORAGE_URI"),
		RedisURL:            os.Getenv("REDIS_URL"),
		SentryDsn:           os.Getenv("SENTRY_DSN"),
		TrustedProxyCIDRs:   os.Getenv("TRUSTED_PROXY_CIDRS"),
		CorsDebug:           strings.EqualFold(strings.TrimSpace(os.Getenv("CORS_DEBUG")), "1") ||
			strings.EqualFold(strings.TrimSpace(os.Getenv("CORS_DEBUG")), "true"),
	}
}

func getenvDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getenvFirstNonEmpty(keys []string, def string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return def
}
