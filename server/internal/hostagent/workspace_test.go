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

func TestWorkspaceControlCacheCannotOverlapAnExecutionTree(t *testing.T) {
	for _, pair := range [][2]string{{"/home/ops", "/home/ops/.jumpserver233"}, {"/home", "/home/ops/.jumpserver233"}, {"/home/ops/.jumpserver233/jobs", "/home/ops/.jumpserver233"}, {"/tmp/root", "/tmp/root/helper"}, {"/srv/work", "/srv/work"}} {
		require.ErrorIs(t, ValidateWorkspaceControl(pair[0], pair[1]), ErrWorkspaceInvalid)
	}
	for _, pair := range [][2]string{{"/home/ops/work", "/home/ops/.jumpserver233"}, {"/tmp/root/workspace", "/tmp/root/jms-agent"}, {"/srv/work", "/srv/work-helper"}} {
		require.NoError(t, ValidateWorkspaceControl(pair[0], pair[1]))
	}
}
