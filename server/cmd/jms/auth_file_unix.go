//go:build !windows

package main

import "os"

func privateAuthTemp(dir string) (*os.File, error) { return os.CreateTemp(dir, ".jms-auth-*") }
