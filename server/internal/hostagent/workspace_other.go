//go:build !linux

package hostagent

func CheckWorkspace(directory string) (WorkspaceStatus, error) {
	return WorkspaceStatus{}, ErrWorkspaceUnavailable
}
func ExecWorkspace(directory, command string, interactive bool) error { return ErrWorkspaceUnavailable }
