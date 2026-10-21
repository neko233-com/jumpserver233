package files

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNativeSFTPRenamePreservesBoundariesAndExistingFiles(t *testing.T) {
	remote := newMemoryRemote()
	remote.files["/home/operator/a"] = []byte("new")
	remote.files["/home/operator/b"] = []byte("old")
	service := NewService(func(context.Context, string) (Remote, error) { return remote, nil }, nil)
	require.ErrorIs(t, service.Rename(context.Background(), "ops", "asset", "a", "b", false), ErrConflict)
	require.Equal(t, []byte("old"), remote.files["/home/operator/b"])
	require.NoError(t, service.Rename(context.Background(), "ops", "asset", "a", "b", true))
	require.Equal(t, []byte("new"), remote.files["/home/operator/b"])
	for _, pair := range [][2]string{{".", "c"}, {"b", "."}, {"b", "../escape"}, {"/etc/passwd", "c"}} {
		require.Error(t, service.Rename(context.Background(), "ops", "asset", pair[0], pair[1], true))
	}
	remote.symlinks["/home/operator/link"] = true
	require.ErrorIs(t, service.Rename(context.Background(), "ops", "asset", "link", "c", false), ErrUnsafePath)
}
