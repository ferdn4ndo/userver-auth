package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTokenService_IssuePair(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	access, accessExp, refresh, refreshExp, err := svc.IssuePair(ctx, uid)
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)
	require.Contains(t, accessExp, "T")
	require.Contains(t, accessExp, "Z")
	require.Contains(t, refreshExp, "Z")

	gotAccess, err := svc.ParseAndValidate(ctx, access, "ACCESS")
	require.NoError(t, err)
	require.Equal(t, uid, gotAccess)

	gotRefresh, err := svc.ParseAndValidate(ctx, refresh, "REFRESH")
	require.NoError(t, err)
	require.Equal(t, uid, gotRefresh)
}

func TestTokenService_ParseAndValidate_malformed(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	_, err := svc.ParseAndValidate(ctx, "not-a-jwt", "ACCESS")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestTokenService_ParseAndValidate_expired(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	past := time.Now().UTC().Add(-2 * time.Hour)
	claims := tokenClaims{
		Typ: "ACCESS",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uid.String(),
			IssuedAt:  jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(time.Minute)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = svc.ParseAndValidate(ctx, tok, "ACCESS")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, he.Message, "expired")
}

func TestTokenService_ParseAndValidate_wrongSecret(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	now := time.Now().UTC()
	claims := tokenClaims{
		Typ: "ACCESS",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uid.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("wrong-secret-key-not-the-same-as-svc!!"))
	require.NoError(t, err)

	_, err = svc.ParseAndValidate(ctx, tok, "ACCESS")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestTokenService_ParseAndValidate_wrongSigningMethod(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	now := time.Now().UTC()
	claims := tokenClaims{
		Typ: "ACCESS",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uid.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = svc.ParseAndValidate(ctx, tok, "ACCESS")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestTokenService_ParseAndValidate_blocked(t *testing.T) {
	ctx := context.Background()
	bl := &stubBlocklist{blocked: map[string]bool{}}
	svc := NewTokenService(testEnv(), bl)
	uid := uuid.New()
	access, _, _, _, err := svc.IssuePair(ctx, uid)
	require.NoError(t, err)
	bl.blocked[access] = true

	_, err = svc.ParseAndValidate(ctx, access, "ACCESS")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, he.Message, "revoked")
}

func TestTokenService_ParseAndValidate_blocklistError(t *testing.T) {
	ctx := context.Background()
	bl := &stubBlocklist{isErr: errors.New("db down")}
	svc := NewTokenService(testEnv(), bl)
	uid := uuid.New()
	access, _, _, _, err := svc.IssuePair(ctx, uid)
	require.NoError(t, err)

	_, err = svc.ParseAndValidate(ctx, access, "ACCESS")
	require.Error(t, err)
	require.Contains(t, err.Error(), "db down")
}

func TestTokenService_ParseAndValidate_wrongTyp(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	access, _, _, _, err := svc.IssuePair(ctx, uid)
	require.NoError(t, err)

	_, err = svc.ParseAndValidate(ctx, access, "REFRESH")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
	require.Contains(t, he.Message, "Wrong token type")
}

func TestTokenService_ParseAndValidate_invalidSubject(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	now := time.Now().UTC()
	claims := tokenClaims{
		Typ: "ACCESS",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "not-a-uuid",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = svc.ParseAndValidate(ctx, tok, "ACCESS")
	require.Error(t, err)
	var he *HTTPError
	require.True(t, errors.As(err, &he))
	require.Equal(t, 401, he.Status)
}

func TestTokenService_ParseAndValidate_whitespaceTrim(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	access, _, _, _, err := svc.IssuePair(ctx, uid)
	require.NoError(t, err)

	got, err := svc.ParseAndValidate(ctx, "  \t"+access+"\n", "ACCESS")
	require.NoError(t, err)
	require.Equal(t, uid, got)
}

func TestTokenService_TokenMeta_ok(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	access, _, _, _, err := svc.IssuePair(ctx, uid)
	require.NoError(t, err)

	issued, exp, err := svc.TokenMeta(access)
	require.NoError(t, err)
	require.Contains(t, issued, "T")
	require.Contains(t, exp, "Z")
}

func TestTokenService_TokenMeta_invalidToken(t *testing.T) {
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	_, _, err := svc.TokenMeta("x.y.z")
	require.Error(t, err)
}

func TestTokenService_TokenMeta_missingIatExp(t *testing.T) {
	svc := NewTokenService(testEnv(), &stubBlocklist{})
	uid := uuid.New()
	claims := tokenClaims{
		Typ: "ACCESS",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: uid.String(),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, _, err = svc.TokenMeta(tok)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing iat/exp")
}
