package hostagent

import (
	"encoding/hex"
	"errors"
	"path"
	"strings"
	"unicode"
)

var (
	ErrWorkspaceInvalid     = errors.New("invalid SSH workspace")
	ErrWorkspaceUnavailable = errors.New("SSH workspace isolation unavailable")
)

// ValidateWorkspace validates a Linux path, independent of the server OS.
// Kernel confinement covers its whole subtree; it is not a command-text rule.
func ValidateWorkspace(directory string) error {
	if directory == "" || len(directory) > 1024 || !path.IsAbs(directory) || path.Clean(directory) != directory || directory == "/" || strings.Contains(directory, "\\") || strings.IndexFunc(directory, unicode.IsControl) >= 0 {
		return ErrWorkspaceInvalid
	}
	// Runtime trees and kernel interfaces must never become writable workspaces.
	for _, reserved := range []string{"/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/run"} {
		if directory == reserved || strings.HasPrefix(directory, reserved+"/") || strings.HasPrefix(reserved, directory+"/") {
			return ErrWorkspaceInvalid
		}
	}
	return nil
}

// Control paths must stay outside operator-writable workspaces. In particular,
// a workspace cannot contain or live inside the pinned helper cache.
func ValidateWorkspaceControl(directory, control string) error {
	if ValidateWorkspace(directory) != nil || !path.IsAbs(control) || path.Clean(control) != control || strings.IndexFunc(control, unicode.IsControl) >= 0 {
		return ErrWorkspaceInvalid
	}
	if directory == control || strings.HasPrefix(control, directory+"/") || strings.HasPrefix(directory, control+"/") {
		return ErrWorkspaceInvalid
	}
	return nil
}

type WorkspaceStatus struct {
	Format           string `json:"format"`
	Directory        string `json:"directory"`
	LandlockABI      int    `json:"landlock_abi"`
	Identity         string `json:"identity"`
	WorkingDirectory string `json:"working_directory,omitempty"`
	WorkingIdentity  string `json:"working_identity,omitempty"`
}

// ValidateWorkingDirectory accepts only a canonical absolute path within the
// configured workspace. The Linux helper separately verifies the opened object.
func ValidateWorkingDirectory(workspace, directory string) error {
	if ValidateWorkspace(workspace) != nil || ValidateWorkspace(directory) != nil || directory != workspace && !strings.HasPrefix(directory, workspace+"/") {
		return ErrWorkspaceInvalid
	}
	return nil
}

func ValidWorkspaceIdentity(identity string) bool {
	_, err := hex.DecodeString(identity)
	return len(identity) == 64 && strings.ToLower(identity) == identity && err == nil
}
