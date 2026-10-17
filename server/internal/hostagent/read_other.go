//go:build !linux

package hostagent

import "os"

func openSnapshot(string) (*os.File, error) { return nil, ErrUnsupported }
func owned(os.FileInfo) bool                { return false }
func trustedAccountFile(os.FileInfo) bool   { return false }
func syncDirectory(string) error            { return ErrUnsupported }
