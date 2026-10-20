//go:build linux && (amd64 || arm64)

package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type workspaceTerminalHarness struct {
	t                     *testing.T
	root                  string
	parentPID             int
	input                 io.WriteCloser
	frames                chan terminalwire.Frame
	readDone, processDone chan struct{}
	cancel                context.CancelFunc
	mu                    sync.Mutex
	output                bytes.Buffer
	sequence              uint64
	close                 sync.Once
	err                   error
}

func workspaceTerminalFixture(t *testing.T) *workspaceTerminalHarness {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	require.NoError(t, os.Mkdir(root, 0700))
	require.NoError(t, os.Mkdir(filepath.Join(root, "sub"), 0700))
	state, e := CheckWorkspace(root)
	if e != nil {
		if os.Getenv("JMS_REQUIRE_WORKSPACE") == "1" {
			t.Fatal(e)
		}
		t.Skip("requires Landlock ABI 3 and directory identity support")
	}
	binary, e := os.ReadFile(filepath.Join("..", "agentbundle", "artifacts", "jms-agent-linux-"+runtime.GOARCH))
	require.NoError(t, e)
	self := filepath.Join(base, "jms-agent")
	require.NoError(t, os.WriteFile(self, binary, 0700))
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	cmd := exec.CommandContext(ctx, self, "workspace-terminal", "--directory", root, "--identity", state.Identity, "--cols", "100", "--rows", "30")
	input, e := cmd.StdinPipe()
	require.NoError(t, e)
	output, e := cmd.StdoutPipe()
	require.NoError(t, e)
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())
	h := &workspaceTerminalHarness{t: t, root: root, parentPID: cmd.Process.Pid, input: input, frames: make(chan terminalwire.Frame, 64), readDone: make(chan struct{}), processDone: make(chan struct{}), cancel: cancel}
	go func() { defer close(h.processDone); h.err = cmd.Wait() }()
	go func() {
		defer close(h.readDone)
		for {
			f, e := terminalwire.Read(output)
			if e != nil {
				return
			}
			if f.Kind == terminalwire.Output {
				h.mu.Lock()
				if h.output.Len() < 128*1024 {
					_, _ = h.output.Write(f.Payload)
				}
				h.mu.Unlock()
			} else {
				select {
				case h.frames <- f:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	t.Cleanup(h.Close)
	f := h.receive()
	require.Equal(t, terminalwire.Hello, f.Kind)
	require.Equal(t, "jms233-directory-terminal-v1", string(f.Payload))
	return h
}
func (h *workspaceTerminalHarness) Close() {
	h.close.Do(func() {
		_ = h.input.Close()
		select {
		case <-h.processDone:
		case <-time.After(3 * time.Second):
			h.cancel()
			select {
			case <-h.processDone:
			case <-time.After(time.Second):
				h.t.Error("owned native terminal did not stop")
			}
		}
		h.cancel()
		select {
		case <-h.readDone:
		case <-time.After(time.Second):
			h.t.Error("owned native terminal reader did not stop")
		}
	})
}
func (h *workspaceTerminalHarness) send(kind byte, id uint64, payload []byte) {
	h.t.Helper()
	require.NoError(h.t, terminalwire.Write(h.input, terminalwire.Frame{Kind: kind, ID: id, Payload: payload}))
}
func (h *workspaceTerminalHarness) receive() terminalwire.Frame {
	h.t.Helper()
	select {
	case f := <-h.frames:
		return f
	case <-h.readDone:
		h.t.Fatal("native terminal closed before expected control response")
	case <-time.After(3 * time.Second):
		h.t.Fatal("native terminal control timed out")
	}
	return terminalwire.Frame{}
}
func (h *workspaceTerminalHarness) acquire() (uint64, terminalwire.Reply) {
	h.t.Helper()
	h.sequence++
	h.send(terminalwire.Acquire, h.sequence, nil)
	frame := h.receive()
	require.Equal(h.t, terminalwire.ProofResult, frame.Kind)
	require.Equal(h.t, h.sequence, frame.ID)
	var reply terminalwire.Reply
	require.NoError(h.t, json.Unmarshal(frame.Payload, &reply))
	return frame.ID, reply
}
func (h *workspaceTerminalHarness) readyProof() (uint64, terminalwire.Proof) {
	h.t.Helper()
	var id uint64
	var reply terminalwire.Reply
	require.Eventually(h.t, func() bool { id, reply = h.acquire(); return reply.Error == "" && reply.Proof.Valid() }, 3*time.Second, 10*time.Millisecond)
	return id, reply.Proof
}
func (h *workspaceTerminalHarness) commit(id uint64, data []byte) {
	h.t.Helper()
	h.send(terminalwire.Commit, id, data)
	frame := h.receive()
	require.Equal(h.t, terminalwire.Acknowledgement, frame.Kind)
	require.Equal(h.t, id, frame.ID)
}
func (h *workspaceTerminalHarness) abort(id uint64) {
	h.send(terminalwire.Abort, id, nil)
	require.Equal(h.t, terminalwire.Acknowledgement, h.receive().Kind)
}
func TestDirectoryTerminalNativeKernelCWDAndOneTimeCommit(t *testing.T) {
	h := workspaceTerminalFixture(t)
	id, p := h.readyProof()
	assert.Equal(t, h.root, p.Directory)
	h.abort(id)
	h.send(terminalwire.Input, 0, []byte("cd sub\r"))
	id, p = h.readyProof()
	require.Equal(t, filepath.Join(h.root, "sub"), p.Directory)
	h.abort(id)
	h.send(terminalwire.Input, 0, []byte("PWD=/forged\r"))
	id, p = h.readyProof()
	assert.Equal(t, filepath.Join(h.root, "sub"), p.Directory)
	h.abort(id)
	h.send(terminalwire.Input, 0, []byte("printf x >> counter"))
	id, _ = h.readyProof()
	h.commit(id, []byte{'\r'})
	h.commit(id, []byte{'\r'})
	require.Eventually(t, func() bool {
		raw, e := os.ReadFile(filepath.Join(h.root, "sub", "counter"))
		return e == nil && string(raw) == "x"
	}, time.Second, 10*time.Millisecond)
	h.Close()
	h.Close()
}
func TestDirectoryTerminalNativeReplacementRejectsBeforeAnyExecution(t *testing.T) {
	h := workspaceTerminalFixture(t)
	id, _ := h.readyProof()
	h.abort(id)
	h.send(terminalwire.Input, 0, []byte("cd sub\r"))
	id, _ = h.readyProof()
	h.abort(id)
	h.send(terminalwire.Input, 0, []byte("printf must-not-run > receipt"))
	id, p := h.readyProof()
	require.Equal(t, filepath.Join(h.root, "sub"), p.Directory)
	require.NoError(t, os.Rename(filepath.Join(h.root, "sub"), filepath.Join(h.root, "previous")))
	require.NoError(t, os.Mkdir(filepath.Join(h.root, "sub"), 0700))
	h.send(terminalwire.Commit, id, []byte{'\r'})
	select {
	case <-h.processDone:
	case <-time.After(3 * time.Second):
		t.Fatal("replaced cwd did not terminate terminal")
	}
	for _, name := range []string{"sub", "previous"} {
		_, e := os.Stat(filepath.Join(h.root, name, "receipt"))
		assert.True(t, os.IsNotExist(e))
	}
}
func TestDirectoryTerminalNativeForegroundCommandsCannotSupplyShellProof(t *testing.T) {
	h := workspaceTerminalFixture(t)
	id, _ := h.readyProof()
	h.abort(id)
	h.send(terminalwire.Input, 0, []byte("sleep 10\r"))
	// The foreground process group belongs to sleep, not the original shell.
	require.Eventually(t, func() bool { h.mu.Lock(); defer h.mu.Unlock(); return strings.Contains(h.output.String(), "sleep 10") }, time.Second, 5*time.Millisecond)
	_, reply := h.acquire()
	assert.Equal(t, "directory_unverified", reply.Error)
	h.Close()
}
func TestDirectoryTerminalNativeClosingAStoppedShellReapsItsProcess(t *testing.T) {
	h := workspaceTerminalFixture(t)
	_, p := h.readyProof()
	require.True(t, p.Valid())
	children := terminalOwnedChildren(h.parentPID)
	require.NotEmpty(t, children)
	// A ptrace stop is held across policy checks; EOF must terminate and join it.
	h.Close()
	h.Close()
	select {
	case <-h.processDone:
	default:
		t.Fatal("native terminal process remained after cleanup")
	}
	for pid, start := range children {
		require.Eventually(t, func() bool {
			current, e := procText(pid, "stat")
			if e != nil {
				return true
			}
			i := strings.LastIndex(current, ") ")
			if i < 0 {
				return false
			}
			fields := strings.Fields(current[i+2:])
			return len(fields) > 19 && fields[19] != start
		}, time.Second, 10*time.Millisecond)
	}
}

func TestDirectoryTerminalNativeQueuedInputNeverBorrowsPreviousDirectory(t *testing.T) {
	h := workspaceTerminalFixture(t)
	id, _ := h.readyProof()
	h.abort(id)
	// Enqueue the previous command and immediately ask for proof, without
	// waiting for its output. A stopped read with a ready result is insufficient.
	h.send(terminalwire.Input, 0, []byte("cd sub\r"))
	id, p := h.readyProof()
	require.Equal(t, filepath.Join(h.root, "sub"), p.Directory)
	h.commit(id, []byte("printf queued > queued-receipt\r"))
	require.Eventually(t, func() bool {
		raw, e := os.ReadFile(filepath.Join(h.root, "sub", "queued-receipt"))
		return e == nil && string(raw) == "queued"
	}, time.Second, 5*time.Millisecond)
	assert.NoFileExists(t, filepath.Join(h.root, "queued-receipt"))
}

func TestDirectoryTerminalReadRestartRejectsCompletedReads(t *testing.T) {
	for _, n := range []int64{-4, -512, -513, -514, -516} {
		assert.True(t, workspaceReadRestart(n))
	}
	for _, n := range []int64{0, 1, 32, -1, -11, -515} {
		assert.False(t, workspaceReadRestart(n))
	}
}

func terminalOwnedChildren(parent int) map[int]string {
	result := map[int]string{}
	tasks, e := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
	if e != nil {
		return result
	}
	for _, task := range tasks {
		text, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, task.Name()))
		if e != nil {
			continue
		}
		for _, value := range strings.Fields(string(text)) {
			pid, e := strconv.Atoi(value)
			if e != nil {
				continue
			}
			stat, e := procText(pid, "stat")
			i := strings.LastIndex(stat, ") ")
			if e != nil || i < 0 {
				continue
			}
			fields := strings.Fields(stat[i+2:])
			if len(fields) > 19 {
				result[pid] = fields[19]
			}
		}
	}
	return result
}
