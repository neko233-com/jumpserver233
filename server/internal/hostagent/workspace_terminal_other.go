//go:build !linux

package hostagent

import (
	"context"
	"io"
)

func ServeWorkspaceTerminal(context.Context, string, string, int, int, io.ReadCloser, io.WriteCloser) error {
	return ErrWorkspaceUnavailable
}
