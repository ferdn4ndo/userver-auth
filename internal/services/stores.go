package services

import (
	"context"

	"github.com/google/uuid"

	"userver-auth/internal/domain/models"
)

// SystemStore is satisfied by *repositories.SystemRepository.
type SystemStore interface {
	GetByName(ctx context.Context, name string) (*models.System, error)
	GetByToken(ctx context.Context, token string) (*models.System, error)
	Create(ctx context.Context, name, token string) (*models.System, error)
	UpdateToken(ctx context.Context, systemID int, newToken string) error
}

// UserStore is satisfied by *repositories.UserRepository.
type UserStore interface {
	GetByUUID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetBySystemAndUsername(ctx context.Context, systemName, username string) (*models.User, error)
	Create(ctx context.Context, u *models.User) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, hashed string) error
	TouchActivity(ctx context.Context, userID uuid.UUID) error
}

// BlocklistStore is satisfied by *repositories.BlocklistRepository.
type BlocklistStore interface {
	IsBlocked(ctx context.Context, token string) (bool, error)
	Add(ctx context.Context, token string) error
}

// TokenIssuer is satisfied by *TokenService (JWT issue/parse/meta).
type TokenIssuer interface {
	IssuePair(ctx context.Context, userID uuid.UUID) (access, accessExp, refresh, refreshExp string, err error)
	ParseAndValidate(ctx context.Context, rawToken, expectedTyp string) (uuid.UUID, error)
	TokenMeta(rawToken string) (issuedAt, expiresAt string, err error)
}
