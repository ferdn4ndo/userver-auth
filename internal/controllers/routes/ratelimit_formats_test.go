package routes

import (
	"testing"

	"github.com/ulule/limiter/v3"
	"github.com/stretchr/testify/require"
)

func TestLimiterFormatsUsedByApp(t *testing.T) {
	for _, f := range []string{"100-D", "1000-H", "10000-H", "1000-D", "10000-D", "100-H"} {
		_, err := limiter.NewRateFromFormatted(f)
		require.NoError(t, err, "format %q", f)
	}
}
