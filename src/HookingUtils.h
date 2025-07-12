#pragma once
#include "headers.h"

typedef struct _ADDRESS_RANGE {
    UINT64 Start;
    UINT64 End;
} ADDRESS_RANGE;

namespace HookingUtils {
	NTSTATUS HookMmIsAddressValid(ADDRESS_RANGE addressToBlock);
    NTSTATUS HookPsLookupProcessByProcessId(UINT32 PidToBlock);
    NTSTATUS DeleteAllHooks();
} // namespace HookingUtils