package jobs

import (
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestAccountUsageRequiresAnExecutedFinishedJob(t *testing.T) {
	at := time.Now().UTC()
	s := &Service{jobs: map[string]Job{
		"ok":               {AssetID: "account", StartedAt: at, State: "succeeded", ExecResult: sshclient.ExecResult{ExitCode: 0}},
		"remote-error":     {AssetID: "account", StartedAt: at.Add(time.Hour), State: "failed", ExecResult: sshclient.ExecResult{ExitCode: 1}},
		"connection-error": {AssetID: "account", StartedAt: at.Add(2 * time.Hour), State: "failed", ExecResult: sshclient.ExecResult{ExitCode: -1}},
		"pending":          {AssetID: "account", StartedAt: at.Add(3 * time.Hour), State: "running"},
	}}
	got := s.AccountUsage(map[string]bool{"account": true})
	assert.Equal(t, at.Add(time.Hour), got["account"])
	assert.Empty(t, s.AccountUsage(map[string]bool{}))
}
