//go:build !linux

package hostagent

func SetWorkspaceInput(input []byte) error {
	if len(input) == 0 {
		return nil
	}
	return ErrWorkspaceUnavailable
}
