//go:build !linux

package hostagent

func CheckWorkspace(directory string) (WorkspaceStatus, error) {
	return WorkspaceStatus{}, ErrWorkspaceUnavailable
}
func ExecWorkspace(directory, command string, interactive bool) error { return ErrWorkspaceUnavailable }

func ExecWorkspaceSFTP(directory string) error { return ErrWorkspaceUnavailable }
func ServeWorkspaceSFTP() error                { return ErrWorkspaceUnavailable }
