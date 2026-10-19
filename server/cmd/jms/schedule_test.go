package main

import (
	"context"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func TestScheduledInstallationCLIRejectsAmbiguousInputs(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"schedule"}, {"schedule-status", "--root", "x", "--revision", "1"}, {"supervise", "--root", "x"}, {"supervise", "--root", "x", "--passphrase-file", "-"}, {"schedule", "--root", "x", "--at", "now"}, {"schedule", "--root", "x", "--at", "2026-10-20T00:00:00Z", "--drain-timeout", "5.1s"}, {"schedule-cancel", "--root", "x", "--sha256", "unexpected"}} {
		require.Error(t, executeSchedule(context.Background(), args, io.Discard, io.Discard))
	}
}
