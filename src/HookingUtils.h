#pragma once
#include "headers.h"

typedef struct _ADDRESS_RANGE {
    UINT64 Start;
    UINT64 End;
} ADDRESS_RANGE;

// i did not hook NtFreeVirtualMemory, to atleast let the kernel free the process memory after use (unless he uses some internal function, I'm guessing he uses NtFreePhysicalMemory or some equivalent to the name, instead of virtual, and just deletes the virtual pages in the table.) -- It's fine to let the free memory stay, as you cant use the memory after without Alloc, which is hooked.
namespace HookingUtils {
	NTSTATUS HookMemory(UINT32 PID);
    NTSTATUS HookPsLookupProcessByProcessId(UINT32 PidToBlock);
    NTSTATUS DeleteAllHooks();
} // namespace HookingUtils