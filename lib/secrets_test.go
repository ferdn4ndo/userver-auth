package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretsEqual(t *testing.T) {
	require.True(t, SecretsEqual("same", "same"))
	require.False(t, SecretsEqual("a", "b"))
	require.True(t, SecretsEqual("", ""))
}
