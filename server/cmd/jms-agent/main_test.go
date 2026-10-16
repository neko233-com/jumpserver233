package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeAgentAcceptsOnlyBoundedRecoveryCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"sh"}, {"check", "--unknown", "value"}, {"restore", "--directory", "x", "extra"}} {
		require.Equal(t, 2, run(args))
	}
	require.Equal(t, 1, run([]string{"check", "--directory", "relative", "--config-sha", "invalid"}))
}
