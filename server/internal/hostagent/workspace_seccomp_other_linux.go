//go:build linux && !amd64 && !arm64

package hostagent

func workspaceSeccomp() error { return ErrWorkspaceUnavailable }
