package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"userver-auth/internal/domain/models"
	"userver-auth/lib"
)

// AuthService implements registration, login, and token flows.
type AuthService struct {
	env       lib.Env
	systems   SystemStore
	users     UserStore
	blocklist BlocklistStore
	tokens    TokenIssuer
}

func NewAuthService(
	env lib.Env,
	systems SystemStore,
	users UserStore,
	blocklist BlocklistStore,
	tokens TokenIssuer,
) *AuthService {
	return &AuthService{env: env, systems: systems, users: users, blocklist: blocklist, tokens: tokens}
}

func (s *AuthService) hashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), s.env.BcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *AuthService) checkPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

func randomURLSafe(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateSystem creates a system when the creation token header is valid (checked in HTTP layer).
func (s *AuthService) CreateSystem(ctx context.Context, name string, tokenOpt *string) (*models.System, error) {
	existing, err := s.systems.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, NewHTTPError(409, "System already exists.")
	}
	tok := ""
	if tokenOpt != nil && *tokenOpt != "" {
		tok = *tokenOpt
		other, err := s.systems.GetByToken(ctx, tok)
		if err != nil {
			return nil, err
		}
		if other != nil {
			return nil, NewHTTPError(409, "Token already in use.")
		}
	} else {
		tok, err = randomURLSafe(32)
		if err != nil {
			return nil, err
		}
	}
	return s.systems.Create(ctx, name, tok)
}

func (s *AuthService) validateSystemCreds(ctx context.Context, systemName, systemToken string) error {
	sys, err := s.systems.GetByName(ctx, systemName)
	if err != nil {
		return err
	}
	if sys == nil || !lib.SecretsEqual(sys.Token, systemToken) {
		return NewHTTPError(401, "Invalid system name/token pair.")
	}
	return nil
}

// Register creates a user and returns nested auth tokens (legacy shape).
func (s *AuthService) Register(ctx context.Context, username, systemName, systemToken, password string, isAdmin bool) (map[string]any, error) {
	if err := s.validateSystemCreds(ctx, systemName, systemToken); err != nil {
		return nil, err
	}
	existing, err := s.users.GetBySystemAndUsername(ctx, systemName, username)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, NewHTTPError(409, "Username '"+username+"' already registered for system '"+systemName+"'!")
	}
	hash, err := s.hashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &models.User{
		SystemName: systemName,
		Username:   username,
		Password:   hash,
		IsAdmin:    isAdmin,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	access, aexp, refresh, rexp, err := s.tokens.IssuePair(ctx, u.UUID)
	if err != nil {
		return nil, err
	}
	_ = s.users.TouchActivity(ctx, u.UUID)
	return map[string]any{
		"username":    u.Username,
		"system_name": u.SystemName,
		"is_admin":    u.IsAdmin,
		"auth": map[string]any{
			"access_token":       access,
			"access_token_exp":   aexp,
			"refresh_token":      refresh,
			"refresh_token_exp":  rexp,
		},
	}, nil
}

// Login returns token fields at the top level (legacy).
func (s *AuthService) Login(ctx context.Context, username, systemName, systemToken, password string) (map[string]any, error) {
	if err := s.validateSystemCreds(ctx, systemName, systemToken); err != nil {
		return nil, err
	}
	u, err := s.users.GetBySystemAndUsername(ctx, systemName, username)
	if err != nil {
		return nil, err
	}
	if u == nil || !s.checkPassword(u.Password, password) {
		return nil, NewHTTPError(401, "Incorrect user credentials.")
	}
	access, aexp, refresh, rexp, err := s.tokens.IssuePair(ctx, u.UUID)
	if err != nil {
		return nil, err
	}
	_ = s.users.TouchActivity(ctx, u.UUID)
	return map[string]any{
		"access_token":       access,
		"access_token_exp":   aexp,
		"refresh_token":      refresh,
		"refresh_token_exp":  rexp,
	}, nil
}

// Refresh issues a new token pair from a refresh JWT.
func (s *AuthService) Refresh(ctx context.Context, refreshRaw string) (map[string]any, error) {
	id, err := s.tokens.ParseAndValidate(ctx, refreshRaw, "REFRESH")
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u == nil {
		_ = s.blocklist.Add(ctx, refreshRaw)
		return nil, NewHTTPError(401, "User is unknown.")
	}
	access, aexp, refresh, rexp, err := s.tokens.IssuePair(ctx, u.UUID)
	if err != nil {
		return nil, err
	}
	_ = s.users.TouchActivity(ctx, u.UUID)
	return map[string]any{
		"access_token":       access,
		"access_token_exp":   aexp,
		"refresh_token":      refresh,
		"refresh_token_exp":  rexp,
	}, nil
}

// Me returns the current user profile and access-token timing metadata.
func (s *AuthService) Me(ctx context.Context, accessRaw string) (map[string]any, error) {
	id, err := s.tokens.ParseAndValidate(ctx, accessRaw, "ACCESS")
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if u == nil {
		_ = s.blocklist.Add(ctx, accessRaw)
		return nil, NewHTTPError(401, "User is unknown.")
	}
	issued, exp, err := s.tokens.TokenMeta(accessRaw)
	if err != nil {
		return nil, NewHTTPError(401, "Invalid token. Please log in again.")
	}
	_ = s.users.TouchActivity(ctx, u.UUID)
	return map[string]any{
		"uuid":             u.UUID.String(),
		"system_name":      u.SystemName,
		"username":         u.Username,
		"registered_at":    FormatAPIDateTime(u.RegisteredAt),
		"last_activity_at": FormatAPIDateTime(u.LastActivityAt),
		"is_admin":         u.IsAdmin,
		"token": map[string]any{
			"issued_at":  issued,
			"expires_at": exp,
		},
	}, nil
}

// LookupUser returns another user in the same system (requires valid access token).
func (s *AuthService) LookupUser(ctx context.Context, accessRaw, systemName, username string) (map[string]any, error) {
	id, err := s.tokens.ParseAndValidate(ctx, accessRaw, "ACCESS")
	if err != nil {
		return nil, err
	}
	logged, err := s.users.GetByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if logged == nil {
		_ = s.blocklist.Add(ctx, accessRaw)
		return nil, NewHTTPError(401, "User is unknown.")
	}
	_ = s.users.TouchActivity(ctx, logged.UUID)
	target, err := s.users.GetBySystemAndUsername(ctx, systemName, username)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, NewHTTPError(404, "Username "+username+" not found for system "+systemName+"!")
	}
	return map[string]any{
		"uuid":             target.UUID.String(),
		"system_name":      target.SystemName,
		"username":         target.Username,
		"registered_at":    FormatAPIDateTime(target.RegisteredAt),
		"last_activity_at": FormatAPIDateTime(target.LastActivityAt),
		"is_admin":         target.IsAdmin,
	}, nil
}

// RotateSystemToken rotates a system API token.
func (s *AuthService) RotateSystemToken(ctx context.Context, systemName, currentToken string, newTokenOpt *string) (map[string]any, error) {
	sys, err := s.systems.GetByName(ctx, systemName)
	if err != nil {
		return nil, err
	}
	if sys == nil {
		return nil, NewHTTPError(404, "System not found.")
	}
	if !lib.SecretsEqual(sys.Token, currentToken) {
		return nil, NewHTTPError(401, "Invalid current system token.")
	}
	newTok := ""
	if newTokenOpt != nil && strings.TrimSpace(*newTokenOpt) != "" {
		newTok = strings.TrimSpace(*newTokenOpt)
		if lib.SecretsEqual(newTok, sys.Token) {
			return map[string]any{"name": sys.Name, "token": newTok}, nil
		}
		other, err := s.systems.GetByToken(ctx, newTok)
		if err != nil {
			return nil, err
		}
		if other != nil {
			return nil, NewHTTPError(409, "Token already in use.")
		}
	} else {
		newTok, err = randomURLSafe(32)
		if err != nil {
			return nil, err
		}
	}
	if err := s.systems.UpdateToken(ctx, sys.ID, newTok); err != nil {
		return nil, err
	}
	return map[string]any{"name": sys.Name, "token": newTok}, nil
}

// ChangePassword updates password for the authenticated user.
func (s *AuthService) ChangePassword(ctx context.Context, accessRaw, currentPassword, newPassword string) error {
	if strings.TrimSpace(newPassword) == "" {
		return NewHTTPError(400, "new_password must not be empty.")
	}
	id, err := s.tokens.ParseAndValidate(ctx, accessRaw, "ACCESS")
	if err != nil {
		return err
	}
	u, err := s.users.GetByUUID(ctx, id)
	if err != nil {
		return err
	}
	if u == nil {
		_ = s.blocklist.Add(ctx, accessRaw)
		return NewHTTPError(401, "User is unknown.")
	}
	if !s.checkPassword(u.Password, currentPassword) {
		return NewHTTPError(401, "Incorrect current password.")
	}
	hash, err := s.hashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, u.UUID, hash); err != nil {
		return err
	}
	return s.users.TouchActivity(ctx, u.UUID)
}

// Logout adds the presented access token to the blocklist.
func (s *AuthService) Logout(ctx context.Context, accessRaw string) error {
	id, err := s.tokens.ParseAndValidate(ctx, accessRaw, "ACCESS")
	if err != nil {
		return err
	}
	u, err := s.users.GetByUUID(ctx, id)
	if err != nil {
		return err
	}
	if u != nil {
		_ = s.users.TouchActivity(ctx, u.UUID)
	}
	return s.blocklist.Add(ctx, accessRaw)
}
