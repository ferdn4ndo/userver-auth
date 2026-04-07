package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"userver-auth/internal/domain/models"
	"userver-auth/lib"
)

// SystemRepository persists systems.
type SystemRepository struct {
	db lib.Database
}

func NewSystemRepository(db lib.Database) *SystemRepository {
	return &SystemRepository{db: db}
}

func (r *SystemRepository) GetByName(ctx context.Context, name string) (*models.System, error) {
	var s models.System
	err := r.db.GetContext(ctx, &s, `SELECT id, name, token, created_at FROM system WHERE name = $1`, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SystemRepository) GetByToken(ctx context.Context, token string) (*models.System, error) {
	var s models.System
	err := r.db.GetContext(ctx, &s, `SELECT id, name, token, created_at FROM system WHERE token = $1`, token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SystemRepository) Create(ctx context.Context, name, token string) (*models.System, error) {
	now := time.Now().UTC()
	var s models.System
	err := r.db.QueryRowxContext(ctx, `
		INSERT INTO system (name, token, created_at)
		VALUES ($1, $2, $3)
		RETURNING id, name, token, created_at
	`, name, token, now).StructScan(&s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SystemRepository) UpdateToken(ctx context.Context, systemID int, newToken string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE system SET token = $1 WHERE id = $2`, newToken, systemID)
	return err
}
