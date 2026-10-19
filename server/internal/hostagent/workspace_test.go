package hostagent

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWorkspacePathsRejectAliasesAndKernelOrRuntimeTrees(t *testing.T) {
	for _, directory := range []string{"", ".", "relative", "/", "/srv/../home", "/srv/work/", "/srv//work", "/tmp/a\n", "/tmp/\\x", "/etc", "/usr/local", "/proc/self/fd", "/dev/shm", "/run/user/1000"} {
		require.ErrorIs(t, ValidateWorkspace(directory), ErrWorkspaceInvalid, directory)
	}
	for _, directory := range []string{"/srv/work", "/home/ops/workspace", "/tmp/work space", "/opt/业务"} {
		require.NoError(t, ValidateWorkspace(directory))
	}
}
