package services

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHTTPError(t *testing.T) {
	e := NewHTTPError(404, "not found")
	require.Equal(t, 404, e.Status)
	require.Equal(t, "not found", e.Message)
	require.Equal(t, "not found", e.Error())
}
