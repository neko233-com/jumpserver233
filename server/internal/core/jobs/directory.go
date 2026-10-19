package jobs

import (
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func validJobDirectory(j Job, version int) bool {
	if j.WorkingDirectory != "" && (hostagent.ValidateWorkspace(j.WorkingDirectory) != nil || j.Plugin != nil || j.Discovery != nil || j.RemoteAccount != nil || j.PlaybookStep != nil) {
		return false
	}
	if j.WorkingDirectory == "" && j.ExecutionDirectory == "" && !strings.HasPrefix(j.ConnectionScope, "cx2-") {
		return true
	}
	if version < 6 {
		return false
	}
	if j.State == "denied" && j.ConnectionScope == "" {
		return j.ExecutionDirectory == ""
	}
	proof, err := accessreviews.ParseConnectionScope(j.ConnectionScope)
	return err == nil && proof.WorkingDirectory == j.ExecutionDirectory && (j.WorkingDirectory == "" || j.WorkingDirectory == proof.WorkingDirectory)
}
