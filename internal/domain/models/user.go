package models

import (
	"time"

	"github.com/google/uuid"
)

// User matches the legacy SQLAlchemy `users` table.
type User struct {
	UUID            uuid.UUID `db:"uuid"`
	SystemName      string    `db:"system_name"`
	Username        string    `db:"username"`
	Password        string    `db:"password"`
	RegisteredAt    time.Time `db:"registered_at"`
	LastActivityAt  time.Time `db:"last_activity_at"`
	IsAdmin         bool      `db:"is_admin"`
}

// System matches the `system` table.
type System struct {
	ID        int       `db:"id"`
	Name      string    `db:"name"`
	Token     string    `db:"token"`
	CreatedAt time.Time `db:"created_at"`
}
