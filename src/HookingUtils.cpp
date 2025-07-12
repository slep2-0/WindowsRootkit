#include "HookingUtils.h"

static BOOLEAN(*OrgMmIsAddressValid)(PVOID) = nullptr;
static NTSTATUS(*OrgPsLookupProcessByProcessId)(HANDLE PID, PEPROCESS *Process) = nullptr;

static volatile ADDRESS_RANGE g_BlockedAddress = { 0x0, 0x0 };
static volatile UINT32 g_PidToBlock = 0;

static bool hasHookedMmIsAddressValid = false;
static bool hasHookedPsLookupByProcessId = false;

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
        DbgPrint("[HOOK] MmIsAddressValid called with fake address: 0x%llx | BLOCKED RANGE: 0x%llx - 0x%llx", givenAddress, g_BlockedAddress.Start, g_BlockedAddress.End);
        return FALSE; // Return FALSE since this address is blocked, so any driver that calls this (or even ntoskrnl) would be blocked -- I'm guessing to myself ntoskrnl doesn't call this though as microsoft themselves know it's a bad function.
    }
    return OrgMmIsAddressValid(VirtualAddress);
}

NTSTATUS HookedPsLookupProcessByProcessId(HANDLE PID, PEPROCESS* Process) {
    UINT32 gottenPid = HandleToUlong(PID);
    if (gottenPid == g_PidToBlock) {
        DbgPrint("[HOOK] PsLookupProcessByProcessId called with PID: %d | BLOCKED.", gottenPid);
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

NTSTATUS HookingUtils::HookMmIsAddressValid(ADDRESS_RANGE addressToBlock) {
    DbgPrint("[+] HookMmIsAddressValid called.\n");
    if (hasHookedMmIsAddressValid) {
        //InterlockedExchange64((volatile LONG64*)&g_BlockedAddress, addressToBlock);
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
    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());
    DetourAttach((void**)&OrgMmIsAddressValid, HookedMmIsAddressValid);
    DetourTransactionCommit();
    DbgPrint("[+] Detours ended - MmIsAddressValid\n");
    //InterlockedExchange64((volatile LONG64*)&g_BlockedAddress, addressToBlock);
    SetRange(addressToBlock.Start, addressToBlock.End);
    hasHookedMmIsAddressValid = true;
    DbgPrint("[+] Finished with hooking MmIsAddressValid\n");
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
    DetourTransactionBegin();
    DetourUpdateThread(ZwCurrentThread());
    if (hasHookedMmIsAddressValid) {
        DetourDetach((void**)&OrgMmIsAddressValid, HookedMmIsAddressValid);
    }
    DetourTransactionCommit();
    return STATUS_SUCCESS;
}