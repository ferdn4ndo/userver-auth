package services

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHealthService_Status(t *testing.T) {
	s := NewHealthService()
	got := s.Status()
	require.Equal(t, "ok", got["status"])
}
