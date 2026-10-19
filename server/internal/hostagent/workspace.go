package hostagent

import (
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

type WorkspaceStatus struct {
	Format      string `json:"format"`
	Directory   string `json:"directory"`
	LandlockABI int    `json:"landlock_abi"`
}
