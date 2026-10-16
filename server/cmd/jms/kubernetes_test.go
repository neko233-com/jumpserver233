package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKubernetesReviewNoticesNameTheNativeProtocol(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	for _, locale := range []string{"zh_CN.UTF-8", "en_US.UTF-8"} {
		t.Setenv("LANG", locale)
		for _, state := range []string{"pending", "approved", "denied", "expired"} {
			message := terminalReviewNotice(state, true)
			assert.Contains(t, message, "Kubernetes")
			assert.NotContains(t, message, "SSH")
			assert.Equal(t, accessReviewNotice(state), terminalReviewNotice(state, false))
		}
	}
}
