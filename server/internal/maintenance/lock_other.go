//go:build !unix && !windows

package maintenance

import "os"

func lockFile(*os.File) error    { return ErrInvalid }
func unlockFile(*os.File)        {}
func syncDirectory(string) error { return ErrInvalid }
