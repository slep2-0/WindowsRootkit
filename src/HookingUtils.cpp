#include "HookingUtils.h"

static BOOLEAN(*OrgMmIsAddressValid)(PVOID ADDRESS) = nullptr;
static NTSTATUS(*OrgMmCopyVirtualMemory)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize) = nullptr;
static NTSTATUS(*OrgPsLookupProcessByProcessId)(HANDLE PID, PEPROCESS *Process) = nullptr;
static NTSTATUS(*OrgZwQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddressOpt, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformationOut, SIZE_T MemoryInformationLength, PSIZE_T ReturnLengthOutOpt);
static NTSTATUS(*OrgNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
static NTSTATUS(*OrgZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
static NTSTATUS(*OrgNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
static volatile ADDRESS_RANGE g_BlockedAddress = { 0x0, 0x0 };
static volatile UINT32 g_PidToAddressBlock = 0;
static volatile UINT32 g_PidToBlock = 0;

static bool hasHookedMmIsAddressValid = false;
static bool hasHookedPsLookupByProcessId = false;
static bool hasHookedMmCopyVirtualMemory = false;
static bool hasHookedZwQueryVirtualMemory = false;
static bool hasHookedNtQueryVirtualMemory = false;
static bool hasHookedZwProtectVirtualMemory = false;
static bool hasHookedNtAllocateVirtualMemory = false;
static bool hasGloballyHooked = false;

WCHAR* ExtractFileNameFully(const WCHAR* fullPath) {
    if (!fullPath) return NULL;

    const WCHAR* lastSlash = fullPath;
    const WCHAR* ptr = fullPath;

    while (*ptr) {
        if (*ptr == L'\\' || *ptr == L'/') {
            lastSlash = ptr + 1;
        }
        ++ptr;
    }

    return (WCHAR*)lastSlash;
}

void SetRange(UINT64 start, UINT64 end) {
    InterlockedExchange64((volatile LONG64*)&g_BlockedAddress.Start, start);
    InterlockedExchange64((volatile LONG64*)&g_BlockedAddress.End, end);
}

BOOLEAN IsAddressInRange(UINT64 address) {
    return (address >= g_BlockedAddress.Start) && (address < g_BlockedAddress.End);
}

BOOLEAN HookedMmIsAddressValid(PVOID VirtualAddress) {
    UINT64 givenAddress = reinterpret_cast<UINT64>(VirtualAddress);
    if (IsAddressInRange(givenAddress)) {
        DbgPrint("[HOOK] MmIsAddressValid called with address: 0x%llx | BLOCKED RANGE: 0x%llx - 0x%llx\n", givenAddress, g_BlockedAddress.Start, g_BlockedAddress.End);
        return FALSE; // Return FALSE since this address is blocked, so any driver that calls this (or even ntoskrnl) would be blocked -- I'm guessing to myself ntoskrnl doesn't call this though as microsoft themselves know it's a bad function.
    }
    return OrgMmIsAddressValid(VirtualAddress);
}

NTSTATUS HookedMmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize) {
    if (IsAddressInRange((UINT64)TargetAddress)) {
        DbgPrint("[HOOK] MmCopyVirtualMemory called with address: 0x%llx | BLOCKED RANGE: 0x%llx - 0x%llx\n", (UINT64)TargetAddress, g_BlockedAddress.Start, g_BlockedAddress.End);
        return STATUS_UNSUCCESSFUL;
    }
    return OrgMmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize);
}

NTSTATUS HookedZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddressOpt, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformationOut, SIZE_T MemoryInformationLength, PSIZE_T ReturnLengthOutOpt) {
    // since we only have a HANDLE we reference it to a PID using Ob.
    PEPROCESS process;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&process, NULL);
    
    if (status == STATUS_SUCCESS) {
        HANDLE PIDhandle = PsGetProcessId(process);
        UINT32 PID = HandleToUlong(PIDhandle);
        if (PID == g_PidToBlock) {
            DbgPrint("[HOOK] ZwQueryVirtualMemory called with protected PID: %d | BLOCKED.\n", PID);
            return STATUS_INVALID_PARAMETER; // ZwQueryVirtualMemory returns 5 values, first is STATUS_SUCCESS, and the other most safe one is STATUS_INVALID_PARAMETER, let's return that.
        }
    }
    DbgPrint("[HOOK-ERROR] HookedZwQueryVirtualMemory: ObReferenceObjectByHandle failed, STATUS: %d\n", status);
    return OrgZwQueryVirtualMemory(ProcessHandle, BaseAddressOpt, MemoryInformationClass, MemoryInformationOut, MemoryInformationLength, ReturnLengthOutOpt);
}

NTSTATUS HookedZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    //remember this is a pointer to a pointer, so we dereference to get the ACTUAL base address.
    UINT64 givenAddress = reinterpret_cast<UINT64>(*BaseAddress);
    if (IsAddressInRange(givenAddress)) {
        DbgPrint("[HOOK] ZwProtectVirtualMemory called with address: 0x%llx | BLOCKED RANGE: 0x%llx - 0x%llx\n", givenAddress, g_BlockedAddress.Start, g_BlockedAddress.End);
        return STATUS_INVALID_PARAMETER;
    }
    return OrgZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS HookedNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    UINT64 givenAddress = reinterpret_cast<UINT64>(*BaseAddress);
    if (IsAddressInRange(givenAddress)) {
        DbgPrint("[HOOK] NtAllocateVirtualMemory called with address: 0x%llx | BLOCKED RANGE: 0x%llx - 0x%llx\n", givenAddress, g_BlockedAddress.Start, g_BlockedAddress.End);
        return STATUS_INVALID_PARAMETER;
    }
    return OrgNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS HookedPsLookupProcessByProcessId(HANDLE PID, PEPROCESS* Process) {
    UINT32 gottenPid = HandleToUlong(PID);
    if (gottenPid == g_PidToBlock) {
        DbgPrint("[HOOK] PsLookupProcessByProcessId called with PID: %d | BLOCKED.\n", gottenPid);
        RTL_OSVERSIONINFOW osVersion;
        NTSTATUS status = RtlGetVersion(&osVersion);
        if (status != STATUS_SUCCESS) {
            return STATUS_INVALID_CID; // Vista+
        }
        ULONG build = osVersion.dwBuildNumber;
        if (build < 6000) {
            return STATUS_INVALID_PARAMETER; // Vista-
        }
        else {
            return STATUS_INVALID_CID; // Vista+
        }
    }
    // return orig function if the pid is the blocked one.
    return OrgPsLookupProcessByProcessId(PID, Process);
}
NTSTATUS HookingUtils::HookMemory(UINT32 PID) {
    DbgPrint("[+] HookMemory called.\n");
    ADDRESS_RANGE addressToBlock;
    MEMORY_BASIC_INFORMATION memInfo;
    CLIENT_ID cid;
    cid.UniqueProcess = UlongToHandle(PID);
    cid.UniqueThread = NULL;
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);

    if (status != STATUS_SUCCESS || !hProcess) {
        DbgPrint("[-] [HOOK-ERROR] ZwOpenProcess returned %d\n", status);
        return status;
    }
    DbgPrint("[+] Got a process handle for PID: %d\n", PID);

    // Get the address range of the current process.
    status = ZwQueryVirtualMemory(hProcess, NULL, MemoryBasicInformation, &memInfo, sizeof(memInfo), NULL);

    if (status != STATUS_SUCCESS) {
        DbgPrint("[-] [HOOK-ERROR] | ZwQueryVirtualMemory returned %d\n", status);
        return status;
    }

    UINT64 baseAddr = MemoryHelper::GetBaseAddress(PID);

    if (!baseAddr || baseAddr == 0) {
        DbgPrint("[-] BaseAddress is 0, returning from HookMemory function\n");
        return STATUS_INVALID_BASE;
    }

    SIZE_T regionSize = memInfo.RegionSize;
    UINT64 endAddr = baseAddr + regionSize;

    addressToBlock.Start = baseAddr;
    addressToBlock.End = endAddr;
    
    if (hasGloballyHooked) {
        //InterlockedExchange64((volatile LONG64*)&g_BlockedAddress, addressToBlock);
        g_PidToAddressBlock = PID;
        SetRange(addressToBlock.Start, addressToBlock.End);
        return STATUS_SUCCESS;
    }
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"MmIsAddressValid");
    // Get the original-actual MmIsAddressValid function pointer, to return incase we don't need it.
    OrgMmIsAddressValid = (decltype(OrgMmIsAddressValid))MmGetSystemRoutineAddress(&routineName);
    if (!OrgMmIsAddressValid) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgMmIsAddressValid is not valid.\n");
        return STATUS_INVALID_ADDRESS;
    }
    UNICODE_STRING routineVirtualMem = RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
    OrgMmCopyVirtualMemory = (decltype(OrgMmCopyVirtualMemory))MmGetSystemRoutineAddress(&routineVirtualMem);
    if (!OrgMmCopyVirtualMemory) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgMmCopyVirtualMemory is not valid\n");
        return STATUS_INVALID_ADDRESS;
    }
    UNICODE_STRING routineZwQueryVirtualMem = RTL_CONSTANT_STRING(L"ZwQueryVirtualMemory");
    OrgZwQueryVirtualMemory = (decltype(OrgZwQueryVirtualMemory))MmGetSystemRoutineAddress(&routineZwQueryVirtualMem);
    if (!OrgZwQueryVirtualMemory) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgZwQueryVirtualMemory is not valid\n");
        return STATUS_INVALID_ADDRESS;
    }
    UNICODE_STRING routineNtQueryVirtualMem = RTL_CONSTANT_STRING(L"NtQueryVirtualMemory");
    OrgNtQueryVirtualMemory = (decltype(OrgNtQueryVirtualMemory))MmGetSystemRoutineAddress(&routineNtQueryVirtualMem);
    if (!OrgNtQueryVirtualMemory) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgNtQueryVirtualMemory is not valid\n");
        return STATUS_INVALID_ADDRESS;
    }
    UNICODE_STRING routineZwProtectVirtualMem = RTL_CONSTANT_STRING(L"ZwProtectVirtualMemory");
    OrgZwProtectVirtualMemory = (decltype(OrgZwProtectVirtualMemory))MmGetSystemRoutineAddress(&routineZwProtectVirtualMem);
    if (!OrgZwProtectVirtualMemory) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgZwProtectVirtualMemory is not valid\n");
        return STATUS_INVALID_ADDRESS;
    }
    UNICODE_STRING routineNtAllocateVirtualMem = RTL_CONSTANT_STRING(L"NtAllocateVirtualMemory");
    OrgNtAllocateVirtualMemory = (decltype(OrgNtAllocateVirtualMemory))MmGetSystemRoutineAddress(&routineNtAllocateVirtualMem);
    if (!OrgNtAllocateVirtualMemory) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgNtAllocateVirtualMemory is not valid\n");
        return STATUS_INVALID_ADDRESS;
    }
    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());
    DetourAttach((void**)&OrgMmIsAddressValid, HookedMmIsAddressValid);
    DetourAttach((void**)&OrgMmCopyVirtualMemory, HookedMmCopyVirtualMemory);
    DetourAttach((void**)&OrgZwQueryVirtualMemory, HookedZwQueryVirtualMemory);
    DetourAttach((void**)&OrgZwProtectVirtualMemory, HookedZwProtectVirtualMemory);
    DetourAttach((void**)&OrgNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
    DetourTransactionCommit();
    DbgPrint("[+] Detours ended - Memory Hooking\n");
    //InterlockedExchange64((volatile LONG64*)&g_BlockedAddress, addressToBlock);
    SetRange(addressToBlock.Start, addressToBlock.End);
    g_PidToAddressBlock = PID;
    hasHookedMmIsAddressValid = true;
    hasHookedMmCopyVirtualMemory = true;
    hasHookedNtQueryVirtualMemory = true;
    hasHookedZwProtectVirtualMemory = true;
    hasHookedNtAllocateVirtualMemory = true;
    hasGloballyHooked = true;
    DbgPrint("[+] Finished with hooking memory functions for process.\n");
    return STATUS_SUCCESS;
}

NTSTATUS HookingUtils::HookPsLookupProcessByProcessId(UINT32 PidToBlock) {
    DbgPrint("[+] HookPsLookupProcessByProcessId called.\n");
    if (hasHookedPsLookupByProcessId) {
        g_PidToBlock = PidToBlock;
        return STATUS_SUCCESS;
    }
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsLookupProcessByProcessId");
    OrgPsLookupProcessByProcessId = (decltype(OrgPsLookupProcessByProcessId))MmGetSystemRoutineAddress(&routineName);
    if (!OrgPsLookupProcessByProcessId) {
        DbgPrint("[-] STATUS_INVALID_ADDRESS returning, OrgPsLookupProcessByProcessId is not valid.\n");
        return STATUS_INVALID_ADDRESS;
    }
    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());
    DetourAttach((void**)&OrgPsLookupProcessByProcessId, HookedPsLookupProcessByProcessId);
    DetourTransactionCommit();
    DbgPrint("[+] Detours ended - PsLookupProcessByProcessId\n");
    g_PidToBlock = PidToBlock;
    hasHookedPsLookupByProcessId = true;
    DbgPrint("[+] Finished with hooking PsLookupProcessByProcessId\n");
    return STATUS_SUCCESS;
}

NTSTATUS HookingUtils::DeleteAllHooks() {
    DbgPrint("[+] DeleteAllHooks function called\n");
    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());
    if (hasHookedMmIsAddressValid) {
        DetourDetach((void**)&OrgMmIsAddressValid, HookedMmIsAddressValid);
    }
    if (hasHookedMmCopyVirtualMemory) {
        DetourDetach((void**)&OrgMmCopyVirtualMemory, HookedMmCopyVirtualMemory);
    }
    if (hasHookedPsLookupByProcessId) {
        DetourDetach((void**)&OrgPsLookupProcessByProcessId, HookedPsLookupProcessByProcessId);
    }
    if (hasHookedZwQueryVirtualMemory) {
        DetourDetach((void**)&OrgZwQueryVirtualMemory, HookedZwQueryVirtualMemory);
    }
    if (hasHookedZwProtectVirtualMemory) {
        DetourDetach((void**)&OrgZwProtectVirtualMemory, HookedZwProtectVirtualMemory);
    }
    if (hasHookedNtAllocateVirtualMemory) {
        DetourDetach((void**)&OrgNtAllocateVirtualMemory, HookedNtAllocateVirtualMemory);
    }
    hasGloballyHooked = false;
    DetourTransactionCommit();
    DbgPrint("[+] Hooks successfully deleted.\n");
    return STATUS_SUCCESS;
}