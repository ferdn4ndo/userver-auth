package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"userver-auth/internal/domain/models"
	"userver-auth/lib"
)

// UserRepository persists users.
type UserRepository struct {
	db lib.Database
}

func NewUserRepository(db lib.Database) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) GetByUUID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	var u models.User
	err := r.db.GetContext(ctx, &u, `
		SELECT uuid, system_name, username, password, registered_at, last_activity_at, is_admin
		FROM users WHERE uuid = $1`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) GetBySystemAndUsername(ctx context.Context, systemName, username string) (*models.User, error) {
	var u models.User
	err := r.db.GetContext(ctx, &u, `
		SELECT uuid, system_name, username, password, registered_at, last_activity_at, is_admin
		FROM users WHERE system_name = $1 AND username = $2`, systemName, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Create(ctx context.Context, u *models.User) error {
	if u.UUID == uuid.Nil {
		u.UUID = uuid.New()
	}
	now := time.Now().UTC()
	if u.RegisteredAt.IsZero() {
		u.RegisteredAt = now
	}
	if u.LastActivityAt.IsZero() {
		u.LastActivityAt = now
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (uuid, system_name, username, password, registered_at, last_activity_at, is_admin)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.UUID, u.SystemName, u.Username, u.Password, u.RegisteredAt, u.LastActivityAt, u.IsAdmin)
	return err
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, hashed string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET password = $1 WHERE uuid = $2`, hashed, userID)
	return err
}

func (r *UserRepository) TouchActivity(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET last_activity_at = $1 WHERE uuid = $2`, time.Now().UTC(), userID)
	return err
}
