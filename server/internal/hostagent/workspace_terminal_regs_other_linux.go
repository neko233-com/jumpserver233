//go:build linux && !amd64 && !arm64

package hostagent

func workspaceInterruptedRead(int) bool { return false }
