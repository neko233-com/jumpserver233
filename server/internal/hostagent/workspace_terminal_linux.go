//go:build linux

package hostagent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/neko233-com/jumpserver233/server/internal/terminalwire"
	"golang.org/x/sys/unix"
)

// ServeWorkspaceTerminal keeps the protocol and procfs outside the confined
// child. The child inherits only its own PTY descriptors and kernel sandbox.
// No socket, PID file, client-supplied PWD or shell prompt supplies cwd proof.
func ServeWorkspaceTerminal(ctx context.Context, root, identity string, cols, rows int, in io.ReadCloser, out io.WriteCloser) error {
	// Linux ptrace relationships belong to an OS thread, not a Go goroutine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if ValidateWorkspace(root) != nil || !ValidWorkspaceIdentity(identity) || cols < 2 || cols > 500 || rows < 2 || rows > 500 {
		return ErrWorkspaceInvalid
	}
	initial, err := CheckWorkspace(root)
	if err != nil || initial.Identity != identity {
		return ErrWorkspaceInvalid
	}
	// This function runs only in the dedicated helper process. Adopt and reap
	// terminal descendants when the interactive shell exits before them.
	signal.Reset(syscall.SIGCHLD)
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		return ErrWorkspaceUnavailable
	}
	master, slave, err := openWorkspacePTY(cols, rows)
	if err != nil {
		return ErrWorkspaceUnavailable
	}
	defer master.Close()
	defer slave.Close()
	self, err := os.Executable()
	if err != nil {
		return ErrWorkspaceUnavailable
	}
	cmd := exec.Command(self, "workspace", "--directory", root, "--identity", identity)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "TERM=xterm-256color"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0, Pdeathsig: syscall.SIGKILL}
	if err = cmd.Start(); err != nil {
		return ErrWorkspaceUnavailable
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return ErrWorkspaceUnavailable
	}
	defer unix.Close(pidfd)
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var writes sync.Mutex
	write := func(f terminalwire.Frame) error {
		writes.Lock()
		defer writes.Unlock()
		return terminalwire.Write(out, f)
	}
	var terminateOnce sync.Once
	terminate := func() {
		terminateOnce.Do(func() {
			_ = unix.Kill(cmd.Process.Pid, unix.SIGSTOP)
			killWorkspaceShellSession(cmd.Process.Pid)
			killWorkspaceShellSession(cmd.Process.Pid)
			_ = cmd.Process.Kill()
			_ = master.Close()
			_ = slave.Close()
			_ = in.Close()
			_ = out.Close()
		})
	}
	stop := context.AfterFunc(life, terminate)
	defer func() {
		cancel()
		stop()
		terminate()
		wg.Wait()
		_ = cmd.Wait()
		reapWorkspaceDescendants()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Leave the session leader unreaped until all its session members have
		// been terminated. Its PID cannot be reused by an unrelated session.
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		for {
			_, e := unix.Poll(fds, -1)
			if e == unix.EINTR {
				continue
			}
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-life.Done():
		case <-timer.C:
		}
		cancel()
	}()
	if err = write(terminalwire.Frame{Kind: terminalwire.Hello, Payload: []byte("jms233-directory-terminal-v1")}); err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buffer := make([]byte, 16*1024)
		for {
			n, e := master.Read(buffer)
			if n > 0 {
				if write(terminalwire.Frame{Kind: terminalwire.Output, Payload: buffer[:n]}) != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}()
	var lease uint64
	var proof terminalwire.Proof
	var expiry *time.Timer
	defer func() {
		if expiry != nil {
			expiry.Stop()
		}
	}()
	var previous uint64
	var previousHash [32]byte
	ack := func(id uint64, code string, p terminalwire.Proof, kind byte) error {
		raw, _ := json.Marshal(terminalwire.Reply{Error: code, Proof: p})
		return write(terminalwire.Frame{Kind: kind, ID: id, Payload: raw})
	}
	for {
		frame, e := terminalwire.Read(in)
		if e != nil {
			if errors.Is(e, io.EOF) || life.Err() != nil {
				return nil
			}
			return terminalwire.ErrProtocol
		}
		switch frame.Kind {
		case terminalwire.Input:
			if frame.ID != 0 || lease != 0 {
				return terminalwire.ErrProtocol
			}
			if _, e = master.Write(frame.Payload); e != nil {
				return e
			}
		case terminalwire.Resize:
			var window terminalwire.Window
			if frame.ID != 0 || json.Unmarshal(frame.Payload, &window) != nil || window.Cols < 2 || window.Cols > 500 || window.Rows < 2 || window.Rows > 500 {
				return terminalwire.ErrProtocol
			}
			if unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(window.Cols), Row: uint16(window.Rows)}) != nil {
				return ErrWorkspaceUnavailable
			}
		case terminalwire.Acquire:
			if frame.ID == 0 || frame.ID <= previous || lease != 0 || len(frame.Payload) != 0 {
				return terminalwire.ErrProtocol
			}
			p, e := freezeWorkspaceShell(life, int(master.Fd()), int(slave.Fd()), cmd.Process.Pid, root, identity)
			if e != nil {
				if ack(frame.ID, "directory_unverified", terminalwire.Proof{}, terminalwire.ProofResult) != nil {
					return ErrWorkspaceUnavailable
				}
				continue
			}
			lease = frame.ID
			proof = p
			// Expiry terminates the terminal. Automatically resuming and accepting a
			// late commit could execute input under an unverified directory.
			expiry = time.AfterFunc(5*time.Second, cancel)
			if ack(frame.ID, "", proof, terminalwire.ProofResult) != nil {
				return ErrWorkspaceUnavailable
			}
		case terminalwire.Commit:
			if len(frame.Payload) > 2048 {
				return terminalwire.ErrProtocol
			}
			hash := sha256.Sum256(frame.Payload)
			if frame.ID == previous && previous != 0 {
				if hash != previousHash {
					return terminalwire.ErrProtocol
				}
				if ack(frame.ID, "", terminalwire.Proof{}, terminalwire.Acknowledgement) != nil {
					return ErrWorkspaceUnavailable
				}
				continue
			}
			if frame.ID == 0 || frame.ID != lease || life.Err() != nil {
				return terminalwire.ErrProtocol
			}
			current, e := workspaceShellProof(cmd.Process.Pid, int(slave.Fd()), root, identity)
			if e != nil || current != proof {
				return ErrWorkspaceUnavailable
			}
			group, e := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPGRP)
			queued, queueError := unix.IoctlGetInt(int(slave.Fd()), unix.TIOCINQ)
			if e != nil || group != cmd.Process.Pid || queueError != nil || queued != 0 {
				return ErrWorkspaceUnavailable
			}
			if _, e = master.Write(frame.Payload); e != nil {
				return e
			}
			previous = lease
			previousHash = hash
			lease = 0
			if expiry != nil {
				expiry.Stop()
				expiry = nil
			}
			if life.Err() != nil || resumeWorkspaceTrace(cmd.Process.Pid, 0) != nil {
				return ErrWorkspaceUnavailable
			}
			if ack(frame.ID, "", terminalwire.Proof{}, terminalwire.Acknowledgement) != nil {
				return ErrWorkspaceUnavailable
			}
		case terminalwire.Abort:
			if frame.ID != lease || lease == 0 || len(frame.Payload) != 0 {
				return terminalwire.ErrProtocol
			}
			lease = 0
			if expiry != nil {
				expiry.Stop()
				expiry = nil
			}
			if life.Err() != nil || resumeWorkspaceTrace(cmd.Process.Pid, 0) != nil {
				return ErrWorkspaceUnavailable
			}
			if ack(frame.ID, "", terminalwire.Proof{}, terminalwire.Acknowledgement) != nil {
				return ErrWorkspaceUnavailable
			}
		default:
			return terminalwire.ErrProtocol
		}
	}
}

func openWorkspacePTY(cols, rows int) (*os.File, *os.File, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master := os.NewFile(uintptr(fd), "workspace-pty")
	fail := func(e error) (*os.File, *os.File, error) { _ = master.Close(); return nil, nil, e }
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return fail(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fail(err)
	}
	if err = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}); err != nil {
		_ = slave.Close()
		return fail(err)
	}
	return master, slave, nil
}

func procText(pid int, name string) (string, error) {
	f, e := os.Open(fmt.Sprintf("/proc/%d/%s", pid, name))
	if e != nil {
		return "", e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || len(b) > 8192 {
		return "", ErrWorkspaceUnavailable
	}
	return string(b), nil
}
func shellStopped(pid int) bool {
	v, e := procText(pid, "status")
	if e != nil {
		return false
	}
	state, owned, single := false, false, false
	for _, line := range strings.Split(v, "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			state = len(fields) > 1 && fields[1] == "t"
		}
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			owned = len(fields) == 2 && fields[1] == strconv.Itoa(unix.Gettid())
		}
		if strings.HasPrefix(line, "Threads:") {
			fields := strings.Fields(line)
			single = len(fields) == 2 && fields[1] == "1"
		}
	}
	return state && owned && single
}
func shellReadingInput(pid int) bool {
	v, e := procText(pid, "syscall")
	if e != nil {
		return false
	}
	fields := strings.Fields(v)
	if len(fields) < 2 {
		return false
	}
	n, e := strconv.ParseUint(fields[0], 0, 64)
	if e != nil || n != uint64(unix.SYS_READ) {
		return false
	}
	fd, e := strconv.ParseUint(fields[1], 0, 64)
	return e == nil && fd == 0
}
func freezeWorkspaceShell(ctx context.Context, master, slave, pid int, root, identity string) (terminalwire.Proof, error) {
	// Only the original foreground shell blocked in read(0) may be measured.
	// Editors, foreground programs and a shell still executing a prior command
	// cannot lend their directory to a later queued command.
	ctx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	for ctx.Err() == nil {
		// Do not attach to the short-lived multithreaded Go bootstrap before it
		// has replaced itself with the confined shell.
		if !workspaceShellImage(pid) {
			return terminalwire.Proof{}, ErrWorkspaceUnavailable
		}
		group, e := unix.IoctlGetInt(master, unix.TIOCGPGRP)
		if e != nil || group != pid {
			return terminalwire.Proof{}, ErrWorkspaceUnavailable
		}
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SEIZE, uintptr(pid), 0, unix.PTRACE_O_EXITKILL, 0, 0)
		if errno != 0 {
			return terminalwire.Proof{}, ErrWorkspaceUnavailable
		}
		if unix.PtraceInterrupt(pid) != nil {
			_ = unix.Kill(pid, unix.SIGKILL)
			return terminalwire.Proof{}, ErrWorkspaceUnavailable
		}
		stopped, interrupt := false, false
		deliver := 0
		for ctx.Err() == nil && !stopped {
			var info unix.Siginfo
			e := unix.Waitid(unix.P_PID, pid, &info, unix.WSTOPPED|unix.WNOHANG|unix.WALL, nil)
			if e != nil && e != unix.EINTR {
				break
			}
			if info.Code != 0 {
				child, stopStatus, valid := workspaceChildStop(info)
				if !valid || child != pid {
					break
				}
				stopped = true
				interrupt = stopStatus&255 == int(unix.SIGTRAP) && stopStatus>>8 == unix.PTRACE_EVENT_STOP
				if !interrupt {
					deliver = stopStatus & 255
				}
			}
			if !stopped {
				select {
				case <-ctx.Done():
				case <-time.After(time.Millisecond):
				}
			}
		}
		queued, queueError := unix.IoctlGetInt(slave, unix.TIOCINQ)
		if interrupt && stopped && queued == 0 && queueError == nil && workspaceInterruptedRead(pid) && shellReadingInput(pid) {
			p, e := workspaceShellProof(pid, slave, root, identity)
			if e == nil {
				return p, nil
			}
		}
		if !stopped || resumeWorkspaceTrace(pid, deliver) != nil {
			_ = unix.Kill(pid, unix.SIGKILL)
			return terminalwire.Proof{}, ErrWorkspaceUnavailable
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Millisecond):
		}
	}
	return terminalwire.Proof{}, ErrWorkspaceUnavailable
}
func workspaceShellProof(pid, slave int, root, identity string) (terminalwire.Proof, error) {
	if !shellStopped(pid) || !shellReadingInput(pid) || !workspaceInterruptedRead(pid) {
		return terminalwire.Proof{}, ErrWorkspaceUnavailable
	}
	var terminal, standardInput unix.Stat_t
	if unix.Fstat(slave, &terminal) != nil || unix.Stat(fmt.Sprintf("/proc/%d/fd/0", pid), &standardInput) != nil || terminal.Dev != standardInput.Dev || terminal.Ino != standardInput.Ino || terminal.Rdev != standardInput.Rdev {
		return terminalwire.Proof{}, ErrWorkspaceUnavailable
	}
	if !workspaceShellImage(pid) {
		return terminalwire.Proof{}, ErrWorkspaceUnavailable
	}
	proc := fmt.Sprintf("/proc/%d/cwd", pid)
	name, e := os.Readlink(proc)
	if e != nil || ValidateWorkingDirectory(root, name) != nil {
		return terminalwire.Proof{}, ErrWorkspaceInvalid
	}
	fd, e := unix.Open(proc, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return terminalwire.Proof{}, ErrWorkspaceUnavailable
	}
	defer unix.Close(fd)
	actual, e := workspaceIdentity(fd)
	if e != nil {
		return terminalwire.Proof{}, e
	}
	checked, e := CheckWorkspaceAt(root, name)
	if e != nil || checked.Identity != identity || checked.WorkingIdentity != actual {
		return terminalwire.Proof{}, ErrWorkspaceInvalid
	}
	p := terminalwire.Proof{Root: root, Directory: name, RootIdentity: identity, DirectoryIdentity: actual}
	if !p.Valid() {
		return terminalwire.Proof{}, ErrWorkspaceInvalid
	}
	return p, nil
}

func resumeWorkspaceTrace(pid, signal int) error {
	_, _, e := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(pid), 0, uintptr(signal), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}
func workspaceReadRestart(value int64) bool {
	return value == -int64(unix.EINTR) || value == -512 || value == -513 || value == -514 || value == -516
}

func workspaceShellImage(pid int) bool {
	var executable, expected unix.Stat_t
	return unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &executable) == nil && unix.Stat("/bin/sh", &expected) == nil && executable.Dev == expected.Dev && executable.Ino == expected.Ino
}

// The published Linux targets have the same 16-byte siginfo header and SIGCHLD
// union layout. Wait for stop events only: observing an exit here must never
// reap the reserved leader PID before its session cleanup.
func workspaceChildStop(info unix.Siginfo) (int, int, bool) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || info.Signo != int32(unix.SIGCHLD) || (info.Code != 4 && info.Code != 5) {
		return 0, 0, false
	}
	child := (*struct {
		PID    int32
		UID    uint32
		Status int32
	})(unsafe.Add(unsafe.Pointer(&info), 16))
	return int(child.PID), int(child.Status), child.PID > 0 && child.Status > 0
}

// Confined descendants cannot create a new session. pidfds and a repeated
// session/start-time check prevent signalling a recycled PID or another task.
func killWorkspaceShellSession(leader int) {
	f, e := os.Open("/proc")
	if e != nil {
		return
	}
	defer f.Close()
	readSession := func(pid int) (int, string, bool) {
		v, e := procText(pid, "stat")
		i := strings.LastIndex(v, ") ")
		if e != nil || i < 0 {
			return 0, "", false
		}
		fields := strings.Fields(v[i+2:])
		if len(fields) < 20 {
			return 0, "", false
		}
		sid, e := strconv.Atoi(fields[3])
		return sid, fields[19], e == nil
	}
	for scanned := 0; scanned < 131072; {
		entries, e := f.ReadDir(256)
		for _, entry := range entries {
			scanned++
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid == leader {
				continue
			}
			sid, start, ok := readSession(pid)
			if !ok || sid != leader {
				continue
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				continue
			}
			currentSid, currentStart, ok := readSession(pid)
			if ok && currentSid == sid && currentStart == start {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			_ = unix.Close(fd)
		}
		if e != nil || len(entries) == 0 {
			return
		}
	}
}

func reapWorkspaceDescendants() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var status unix.WaitStatus
		pid, e := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if e == unix.ECHILD {
			return
		}
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return
		}
		if pid == 0 {
			time.Sleep(time.Millisecond)
		}
	}
}
