//go:build !linux

package hostagent

func stateLock(string) (func(), error) { return nil, ErrUnsupported }
