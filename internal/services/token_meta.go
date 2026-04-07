package services

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// TokenMeta returns issued_at / expires_at strings matching the legacy API.
func (s *TokenService) TokenMeta(rawToken string) (issuedAt, expiresAt string, err error) {
	claims := &tokenClaims{}
	_, err = jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil {
		return "", "", err
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return "", "", fmt.Errorf("missing iat/exp")
	}
	return FormatAPIDateTime(claims.IssuedAt.Time), FormatAPIDateTime(claims.ExpiresAt.Time), nil
}
