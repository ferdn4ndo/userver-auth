package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"userver-auth/lib"
)

// BlocklistRepository stores revoked JWTs (refresh or access).
type BlocklistRepository struct {
	db lib.Database
}

func NewBlocklistRepository(db lib.Database) *BlocklistRepository {
	return &BlocklistRepository{db: db}
}

func (r *BlocklistRepository) IsBlocked(ctx context.Context, token string) (bool, error) {
	var n int
	err := r.db.GetContext(ctx, &n, `SELECT 1 FROM blocklist_tokens WHERE token = $1 LIMIT 1`, token)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *BlocklistRepository) Add(ctx context.Context, token string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO blocklist_tokens (token, blocked_at) VALUES ($1, $2)
		ON CONFLICT (token) DO NOTHING`,
		token, time.Now().UTC())
	return err
}
