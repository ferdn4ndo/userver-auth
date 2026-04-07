package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFormatAPIDateTime(t *testing.T) {
	ts := time.Date(2026, 4, 7, 15, 4, 5, 123456789, time.FixedZone("CET", 3600))
	got := FormatAPIDateTime(ts)
	require.Equal(t, "2026-04-07T14:04:05.123Z", got)
}
