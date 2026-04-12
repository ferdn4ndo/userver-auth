package routes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"userver-auth/lib"
)

func TestSplitRateFormats(t *testing.T) {
	require.Equal(t, []string{"60-M", "1000-D"}, splitRateFormats("60-M , 1000-D "))
	require.Nil(t, splitRateFormats("  ,  "))
}

func TestGlobalFormatsFromEnv_customProdCSV(t *testing.T) {
	e := lib.Env{EnvMode: "prod", RatelimitGlobalProd: "500-D,30-M"}
	require.Equal(t, []string{"500-D", "30-M"}, globalFormatsFromEnv(e))
}

func TestGlobalFormatsFromEnv_fallbackWhenEmpty(t *testing.T) {
	e := lib.Env{EnvMode: "prod", RatelimitGlobalProd: " , "}
	require.Equal(t, []string{"1000-D"}, globalFormatsFromEnv(e))
	e2 := lib.Env{EnvMode: "development", RatelimitGlobalDev: ",,"}
	require.Equal(t, []string{"10000-D", "100-H"}, globalFormatsFromEnv(e2))
}
