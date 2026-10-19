//go:build !linux

package hostagent

func CheckWorkspace(directory string) (WorkspaceStatus, error) {
	return WorkspaceStatus{}, ErrWorkspaceUnavailable
}
func CheckWorkspaceAt(directory, workingDirectory string) (WorkspaceStatus, error) {
	return WorkspaceStatus{}, ErrWorkspaceUnavailable
}
func ExecWorkspaceAt(directory, workingDirectory, command, rootIdentity, workingIdentity string) error {
	return ErrWorkspaceUnavailable
}
func ExecWorkspace(directory, command string, interactive bool, expected ...string) error {
	return ErrWorkspaceUnavailable
}

func ExecWorkspaceSFTP(directory string, expected ...string) error { return ErrWorkspaceUnavailable }
func ServeWorkspaceSFTP() error                                    { return ErrWorkspaceUnavailable }
