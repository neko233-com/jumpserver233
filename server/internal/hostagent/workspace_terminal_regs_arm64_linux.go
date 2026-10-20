//go:build linux && arm64

package hostagent

import "golang.org/x/sys/unix"

func workspaceInterruptedRead(pid int) bool {
	var regs unix.PtraceRegs
	return unix.PtraceGetRegs(pid, &regs) == nil && regs.Regs[8] == uint64(unix.SYS_READ) && workspaceReadRestart(int64(regs.Regs[0]))
}
