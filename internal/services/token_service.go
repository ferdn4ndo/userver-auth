package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"userver-auth/lib"
)

// TokenService issues and validates HS256 JWTs compatible with the Python service.
type TokenService struct {
	env        lib.Env
	blocklist  BlocklistStore
	secret     []byte
	accessDur  time.Duration
	refreshDur time.Duration
}

func NewTokenService(env lib.Env, blocklist BlocklistStore) *TokenService {
	return &TokenService{
		env:        env,
		blocklist:  blocklist,
		secret:     []byte(env.AppSecretKey),
		accessDur:  time.Duration(env.JWTExpDeltaSecs) * time.Second,
		refreshDur: time.Duration(env.JWTRefreshDeltaSecs) * time.Second,
	}
}

type tokenClaims struct {
	Typ string `json:"typ"`
	jwt.RegisteredClaims
}

// IssuePair returns access/refresh tokens and RFC3339-like exp strings (legacy API).
func (s *TokenService) IssuePair(ctx context.Context, userID uuid.UUID) (access, accessExp, refresh, refreshExp string, err error) {
	now := time.Now().UTC()
	access, accessExp, err = s.sign(userID, "ACCESS", now, s.accessDur)
	if err != nil {
		return "", "", "", "", err
	}
	refresh, refreshExp, err = s.sign(userID, "REFRESH", now, s.refreshDur)
	if err != nil {
		return "", "", "", "", err
	}
	return access, accessExp, refresh, refreshExp, nil
}

func (s *TokenService) sign(userID uuid.UUID, typ string, now time.Time, ttl time.Duration) (token, expStr string, err error) {
	exp := now.Add(ttl)
	claims := tokenClaims{
		Typ: typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString(s.secret)
	if err != nil {
		return "", "", err
	}
	return signed, FormatAPIDateTime(exp), nil
}

// ParseAndValidate decodes a JWT, enforces typ, expiry, signature, and blocklist.
func (s *TokenService) ParseAndValidate(ctx context.Context, rawToken, expectedTyp string) (uuid.UUID, error) {
	rawToken = strings.TrimSpace(rawToken)
	claims := &tokenClaims{}
	parsed, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return uuid.Nil, NewHTTPError(401, "Signature expired. Please log in again.")
		}
		return uuid.Nil, NewHTTPError(401, "Invalid token. Please log in again.")
	}
	if !parsed.Valid {
		return uuid.Nil, NewHTTPError(401, "Invalid token. Please log in again.")
	}
	bl, err := s.blocklist.IsBlocked(ctx, rawToken)
	if err != nil {
		return uuid.Nil, err
	}
	if bl {
		return uuid.Nil, NewHTTPError(401, "This token has been revoked. Please log in again.")
	}
	if !strings.EqualFold(claims.Typ, expectedTyp) {
		return uuid.Nil, NewHTTPError(401, fmt.Sprintf(
			"Wrong token type! Tried to authenticate using %s token, expected %s one.",
			claims.Typ, strings.ToLower(expectedTyp),
		))
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, NewHTTPError(401, "Invalid token. Please log in again.")
	}
	return id, nil
}
