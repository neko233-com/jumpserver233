package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPackagerRejectsInvalidReleaseIdentityBeforeBuilding(t *testing.T) {
	for _, args := range [][]string{{}, {"--version", "v1.2.3-rc.1"}, {"--version", "v1.2.3", "--commit", "wrong", "--built-at", "2026-10-19T00:00:00Z", "--target", "linux/amd64"}, {"--version", "v1.2.3", "--target", "linux/unknown"}} {
		assert.Error(t, run(args))
	}
}
