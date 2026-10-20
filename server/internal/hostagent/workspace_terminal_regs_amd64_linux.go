//go:build linux && amd64

package hostagent

import "golang.org/x/sys/unix"

func workspaceInterruptedRead(pid int) bool {
	var regs unix.PtraceRegs
	return unix.PtraceGetRegs(pid, &regs) == nil && regs.Orig_rax == uint64(unix.SYS_READ) && regs.Rdi == 0 && workspaceReadRestart(int64(regs.Rax))
}
