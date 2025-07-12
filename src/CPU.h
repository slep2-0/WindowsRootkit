#pragma once
#include "headers.h"

#define MSR_LSTAR 0xC0000082
#define MAX_SYSCALLS 256

namespace CPU {
	void RedirectLSTARSyscall(PVOID newFunction);
	bool BlockSyscall(UINT64 syscall);
	void ObliterateLSTAR();
}