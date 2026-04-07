package services

import (
	"context"

	"userver-auth/lib"
)

const testJWTSecret = "unit-test-secret-key-min-32-characters!"

func testEnv() lib.Env {
	return lib.Env{
		AppSecretKey:        testJWTSecret,
		JWTExpDeltaSecs:     3600,
		JWTRefreshDeltaSecs: 7200,
		BcryptCost:          4,
	}
}

// stubBlocklist implements BlocklistStore for tests.
type stubBlocklist struct {
	blocked map[string]bool
	isErr   error
	addErr  error
	Added   []string
}

func (s *stubBlocklist) IsBlocked(ctx context.Context, token string) (bool, error) {
	if s.isErr != nil {
		return false, s.isErr
	}
	if s.blocked == nil {
		return false, nil
	}
	return s.blocked[token], nil
}

func (s *stubBlocklist) Add(ctx context.Context, token string) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.Added = append(s.Added, token)
	return nil
}
