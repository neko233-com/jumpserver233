//go:build linux

package hostagent

import "golang.org/x/sys/unix"

// SetWorkspaceInput passes bounded input through an anonymous pipe. It never
// enters a command argument, audit line or temporary file.
func SetWorkspaceInput(input []byte) error {
	if len(input) == 0 {
		return nil
	}
	if len(input) > 2048 {
		return ErrWorkspaceInvalid
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		return ErrWorkspaceUnavailable
	}
	defer unix.Close(pipe[0])
	n, err := unix.Write(pipe[1], input)
	_ = unix.Close(pipe[1])
	if err != nil || n != len(input) {
		return ErrWorkspaceUnavailable
	}
	if unix.Dup3(pipe[0], 0, 0) != nil {
		return ErrWorkspaceUnavailable
	}
	return nil
}
