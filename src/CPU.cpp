#include "CPU.h"

void CPU::RedirectLSTARSyscall(PVOID newFunction) {
	__try {
		__writemsr(MSR_LSTAR, (UINT64)newFunction);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return;
	}
}

UINT64 BlockedSyscalls[MAX_SYSCALLS];
int blockedCount = 0;

void SyscallHandler() {
	return;
}

bool CPU::BlockSyscall(UINT64 syscall) {
	if (blockedCount >= MAX_SYSCALLS) {
		return false;
	}
	RedirectLSTARSyscall(&SyscallHandler);
	BlockedSyscalls[blockedCount++] = syscall;
	return true;
}

