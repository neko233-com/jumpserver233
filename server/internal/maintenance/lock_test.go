package maintenance

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDataLockProcessExclusionAndCrashRelease(t *testing.T) {
	if os.Getenv("JMS233_TEST_LOCK_CHILD") == "yes" {
		lock, e := Acquire(os.Getenv("JMS233_TEST_LOCK_DIR"))
		if e != nil {
			fmt.Println("busy")
			return
		}
		defer lock.Close()
		fmt.Println("locked")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		return
	}
	data := filepath.Join(t.TempDir(), "data")
	lock, e := Acquire(data)
	require.NoError(t, e)
	child := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDataLockProcessExclusionAndCrashRelease$")
		cmd.Env = append(os.Environ(), "JMS233_TEST_LOCK_CHILD=yes", "JMS233_TEST_LOCK_DIR="+data)
		return cmd
	}
	cmd := child()
	out, e := cmd.CombinedOutput()
	require.NoError(t, e)
	assert.Contains(t, string(out), "busy")
	require.NoError(t, lock.Close())
	cmd = child()
	stdout, e := cmd.StdoutPipe()
	require.NoError(t, e)
	stdin, e := cmd.StdinPipe()
	require.NoError(t, e)
	defer stdin.Close()
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	scanner := bufio.NewScanner(stdout)
	require.True(t, scanner.Scan())
	require.Equal(t, "locked", scanner.Text())
	_, e = Acquire(data)
	assert.ErrorIs(t, e, ErrBusy)
	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()
	lock, e = Acquire(data)
	require.NoError(t, e)
	require.NoError(t, lock.Close())
}
func TestDataLockRejectsNonregularLockFile(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(filepath.Join(data, controlName, "lock"), 0700))
	_, e := Acquire(data)
	assert.ErrorIs(t, e, ErrBusy)
}
