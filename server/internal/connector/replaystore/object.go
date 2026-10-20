// Package replaystore transfers opaque encrypted recording objects.
package replaystore

import (
	"context"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
)

var (
	ErrInvalid     = errors.New("invalid replay storage configuration or object")
	ErrNotFound    = errors.New("replay object not found")
	ErrExists      = errors.New("replay object already exists")
	ErrUnavailable = errors.New("replay storage unavailable")
	ErrIntegrity   = errors.New("replay object integrity mismatch")
)

const MaxObjectBytes int64 = 1 << 30

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,767}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ValidKey(key string) bool {
	return keyPattern.MatchString(key) && path.Clean(key) == key && !strings.HasSuffix(key, "/") && !strings.Contains(key, "..")
}
func ValidDigest(digest string) bool { return digestPattern.MatchString(digest) }

type Objects interface {
	Put(context.Context, string, io.Reader, int64, string) error
	Get(context.Context, string) (io.ReadCloser, error)
	Close() error
}
