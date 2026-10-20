package api

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

func validateOperationDirectoryAsset(d Dependencies, id, directory string) error {
	if directory == "" {
		return nil
	}
	if d.Assets == nil {
		return jobs.ErrInvalid
	}
	a, err := d.Assets.Get(id)
	if err != nil || !assets.IsSSH(a) || hostagent.ValidateWorkingDirectory(a.SSHWorkspace, directory) != nil {
		return jobs.ErrInvalid
	}
	return nil
}

// The metadata admission check cannot treat a requested directory as verified.
// Defer only an unknown-directory decision to the real job's pinned preflight;
// a known denial remains a denial, and no SSH command is admitted here.
func operationDirectoryProofPossible(d Dependencies, id, directory string) bool {
	if d.Assets == nil {
		return false
	}
	a, err := d.Assets.Get(id)
	if err != nil || !assets.IsSSH(a) {
		return false
	}
	if directory == "" {
		directory = a.SSHWorkspace
	}
	return hostagent.ValidateWorkingDirectory(a.SSHWorkspace, directory) == nil
}
