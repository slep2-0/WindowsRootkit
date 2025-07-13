#include "MemoryHelper.h"


PVOID gSharedBuffer = NULL;
PKEVENT gUserEvent = NULL;
HANDLE gSectionHandle = NULL;

namespace MemoryHelper {

    VOID MSGClient(const char* MSG) {
        if (!MSG || !gSharedBuffer || !gUserEvent) {
            DbgPrint("[!] Invalid parameters or uninitialized shared memory\n");
            return;
        }

        // Get message length and validate against buffer size
        size_t msgLen = strlen(MSG) + 1;
        if (msgLen > SHARED_MEM_SIZE) {
            DbgPrint("[!] Message too large for shared buffer\n");
            return;
        }

        // Use try-except to handle potential memory access violations (happened to me with MEMORY_MANAGEMENT stop code..)
        __try {
            // Clear buffer first
            RtlZeroMemory(gSharedBuffer, SHARED_MEM_SIZE);

            // Copy message safely
            RtlCopyMemory(gSharedBuffer, MSG, msgLen);

            // Signal the event
            KeSetEvent(gUserEvent, IO_NO_INCREMENT, FALSE);

            // Wait for 1 second
            LARGE_INTEGER interval;
            interval.QuadPart = -10 * 1000 * 1000;
            KeDelayExecutionThread(KernelMode, FALSE, &interval);

            // Clear buffer after delay - This will be null-terminated everywhere basically.
            RtlZeroMemory(gSharedBuffer, SHARED_MEM_SIZE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[!] Exception occurred in MSGClient\n");
        }
    }

    NTSTATUS SetupSharedMemory() {
        // Shared Memory setup.
        // Properties init.
        NTSTATUS statusMemory;
        UNICODE_STRING sectionName = RTL_CONSTANT_STRING(SECTION_NAME);
        OBJECT_ATTRIBUTES secAttr;
        InitializeObjectAttributes(&secAttr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
        // Max size of memory section
        LARGE_INTEGER maxSize;
        maxSize.QuadPart = SHARED_MEM_SIZE;

        // Setup shared memory section.
        statusMemory = ZwCreateSection(&gSectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &secAttr, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
        if (!NT_SUCCESS(statusMemory)) {
            DbgPrint("[-] Failed to setup ZwCreateSection, status code: %08X\n", statusMemory);
            return statusMemory;
        }
        SIZE_T viewSize = SHARED_MEM_SIZE;
        statusMemory = ZwMapViewOfSection(gSectionHandle, ZwCurrentProcess(), &gSharedBuffer, 0, SHARED_MEM_SIZE, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(statusMemory)) {
            DbgPrint("[-] Failed to setup ZwMapViewOfSection, status code: %08X\n", statusMemory);
            return statusMemory;
        }
        // Setup event to notify client.
        UNICODE_STRING eventName = RTL_CONSTANT_STRING(EVENT_NAME);
        OBJECT_ATTRIBUTES evtAttr;
        InitializeObjectAttributes(&evtAttr, &eventName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);

        // Create the event
        HANDLE hUserEvent = NULL;
        statusMemory = ZwCreateEvent(&hUserEvent,
            EVENT_ALL_ACCESS,
            &evtAttr,
            NotificationEvent,  // Manual reset event
            FALSE);            // Initial state is non-signaled
        if (!NT_SUCCESS(statusMemory)) {
            DbgPrint("[-] Failed to create event, status code: %08X\n", statusMemory);
            return statusMemory;
        }

        // Convert the handle to PKEVENT for kernel use
        statusMemory = ObReferenceObjectByHandle(hUserEvent,
            EVENT_ALL_ACCESS,
            *ExEventObjectType,
            KernelMode,
            (PVOID*)&gUserEvent,
            NULL);
        if (!NT_SUCCESS(statusMemory)) {
            DbgPrint("[-] Failed to reference event object, status code: %08X\n", statusMemory);
            ZwClose(hUserEvent);
            return statusMemory;
        }

        // We can close the handle now since we have the PKEVENT
        ZwClose(hUserEvent);
        DbgPrint("[+] Event created successfully\n");
        return statusMemory;
    }

    void CleanupSharedMemory() {
        DbgPrint("[++] Cleanup of shared memory.\n");
        if (gUserEvent) {
            ObDereferenceObject(gUserEvent);
            DbgPrint("[+] Cleaned gUserEvent\n");
        }
        if (gSharedBuffer) {
            ZwUnmapViewOfSection(ZwCurrentProcess(), gSharedBuffer);
            DbgPrint("[+] Cleaned gSharedBuffer\n");
        }
        if (gSectionHandle) {
            ZwClose(gSectionHandle);
            DbgPrint("[+] Cleaned gSectionHandle\n");
        }
    }


    PVOID GetModuleBase(PEPROCESS process, const WCHAR* moduleName) {
        // this works by getting the process PEB, then iterating over all DLL's until we find moduleName, compare with our dll name, and if it matches get it's base.
        PVOID moduleBase = nullptr;
        LARGE_INTEGER time;
        // define a time
        time.QuadPart = -100ll * 10 * 1000; // 100ms delay

        PREALPEB targetPeb = (PREALPEB)PsGetProcessPeb(process);

        if (!targetPeb)
            return moduleBase;

        for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
            KeDelayExecutionThread(KernelMode, FALSE, &time); // delay execution until we get a valid ldr.
        }
        // if still no ldr, just return a nullptr.
        if (!targetPeb->LoaderData)
            return moduleBase;

        for (PLIST_ENTRY list = targetPeb->LoaderData->InLoadOrderModuleList.Flink; list != &targetPeb->LoaderData->InLoadOrderModuleList; list = list->Flink) {
            // iterate over LDR of the peb to find our dll.
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks); // get our first entry.
            if (entry->FullDllName.Length > 0 && entry->FullDllName.Buffer != NULL && entry->FullDllName.Buffer[0] != L'\0') /*is it valid?*/ {
                if (_wcsicmp(moduleName, entry->BaseDllName.Buffer) == 0) {
                    // this is our DLL.
                    return entry->DllBase;
                }
            }
        }
        return nullptr;
    }

    // basically GetProcAddress.
    PVOID GetProcAddress(PVOID moduleBase, const CHAR* functionName) {
        // this works by parsing the PE and NT headers of the DLL (from the base + offsets) and so getting the exports of the DLL, and from there locating our functionName export, and return that PVOID address.
        PVOID addr = nullptr;
        // reinterpret the bits of the address to the same bits of the PIMAGE_DOS_HEADER.
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);

        if (!dosHeader) {
            return addr;
        }

        // if it doesnt match the standard DOS signature, this is not a valid DOS header. idk why it's called magic number though, probably microsoft developers being clowns.
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return addr;
        }
        // lfanew is "new" because the nt headers came after the DOS headers after transitioning or however you say that word to the NT system after Windows 98 -> XP, i think :)
        PFULL_IMAGE_NT_HEADERS ntheader = reinterpret_cast<PFULL_IMAGE_NT_HEADERS>((PUCHAR)moduleBase + dosHeader->e_lfanew);

        if (!ntheader || ntheader->Signature != IMAGE_NT_SIGNATURE) {
            //invalid nt header.
            return addr;
        }

        IMAGE_OPTIONAL_HEADER optHeader = ntheader->OptionalHeader;

        if (optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
            // invalid data directory for optional header, so invalid header.
            return addr;
        }

        // go over exports now.
        PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((PUCHAR)moduleBase + optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + exportDir->AddressOfFunctions);
        DWORD* names = (DWORD*)((PUCHAR)moduleBase + exportDir->AddressOfNames);
        WORD* ordinals = (WORD*)((PUCHAR)moduleBase + exportDir->AddressOfNameOrdinals);

        for (unsigned long i = 0; i < exportDir->NumberOfNames; i++) {
            // iterate over all function names for the DLL. (if moduleBase is the address of kernel32.dll -> iterate over all export function names of kernel32.dll until we encounter the one we want)
            if (_stricmp((char*)((PUCHAR)moduleBase + names[i]), functionName) == 0) {
                // this is our function name! return its address.
                return (PUCHAR)moduleBase + addresses[ordinals[i]]; // return the function address in slot of ordinals[i] so the i we have been iterating so far. (ordinals is the current slot of the address export list.
            }
        }

        // not found.. return nullptr
        return nullptr;
    }

    NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode, bool alignAddr) {
        // This is taken from the Nidhogg repository, but from what I understand, this first does some checks on the addresses to see that they are valid.
        // It changes protection on the memory incase it didn't have write permissions already, remember that even with kernel level access we cannot "bypass" permissions, those are enforced by the paging in NTOSKRNL.
        // Then it uses the undocumented func MmCopyVirtualMemory.
        // And cleanup.
        HANDLE hTargetProcess;
        ULONG oldProtection;
        SIZE_T patchLen;
        SIZE_T bytesWritten;
        NTSTATUS status = STATUS_SUCCESS;
        SIZE_T alignment = alignAddr ? dataSize : 1;

        if (mode != KernelMode && mode != UserMode)
            return STATUS_UNSUCCESSFUL;

        // Making sure that the given kernel mode address is valid.
        if (mode == KernelMode) {
            // 1 Source must be in kernel‑mode space.
            if (!VALID_KERNELMODE_MEMORY((DWORD64)sourceDataAddress)) {
                return STATUS_UNSUCCESSFUL;
            }

            // 2 Target: if it’s not in kernel space, probe it safely.
            if (!VALID_KERNELMODE_MEMORY((DWORD64)targetAddress)) {
                NTSTATUS probeStatus = ProbeAddress(
                    targetAddress,
                    dataSize,
                    (ULONG)alignment,
                    STATUS_UNSUCCESSFUL
                );
                if (!NT_SUCCESS(probeStatus)) {
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }



        else if (mode == UserMode && (
            !NT_SUCCESS(ProbeAddress(sourceDataAddress, dataSize, (ULONG)dataSize, STATUS_UNSUCCESSFUL)) ||
            (!VALID_KERNELMODE_MEMORY((DWORD64)targetAddress) &&
                !NT_SUCCESS(ProbeAddress(targetAddress, dataSize, (ULONG)alignment, STATUS_UNSUCCESSFUL))))) {
            status = STATUS_UNSUCCESSFUL;
            return status;
        }

        // Adding write permissions.
        status = ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        patchLen = dataSize;
        PVOID addressToProtect = targetAddress;
        status = ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);

        if (!NT_SUCCESS(status)) {
            ZwClose(hTargetProcess);
            return status;
        }
        ZwClose(hTargetProcess);

        // Writing the data.
        status = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceDataAddress, TargetProcess, targetAddress, dataSize, KernelMode, &bytesWritten);

        // Restoring permissions and cleaning up.
        if (ObOpenObjectByPointer(TargetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, (KPROCESSOR_MODE)mode, &hTargetProcess) == STATUS_SUCCESS) {
            patchLen = dataSize;
            ZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
            ZwClose(hTargetProcess);
        }

        return status;
    }
    /*
    template <typename PointerType>
    PointerType AllocateMemory(size_t size, bool paged, bool forceDeprecatedAlloc) {
        PVOID allocatedMem = NULL;

        if (AllocatePool2 && WindowsBuildNumber >= WIN_2004 && !forceDeprecatedAlloc) {
            allocatedMem = paged ? ((tExAllocatePool2)AllocatePool2)(POOL_FLAG_PAGED, size, DRIVER_TAG) :
                ((tExAllocatePool2)AllocatePool2)(POOL_FLAG_NON_PAGED, size, DRIVER_TAG);
        }
        else {
#pragma warning( push )
#pragma warning( disable : 4996)
            allocatedMem = paged ? ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG) :
                ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
#pragma warning( pop )
        }

        if (allocatedMem)
            RtlSecureZeroMemory(allocatedMem, size);
        return reinterpret_cast<PointerType>(allocatedMem);
    }
    */
    NTSTATUS ProbeAddress(PVOID address, SIZE_T len, ULONG alignment, NTSTATUS failureCode) {
        NTSTATUS status = STATUS_SUCCESS;

        if (!VALID_USERMODE_MEMORY((ULONGLONG)address))
            return STATUS_ABANDONED;

        __try {
            ProbeForRead(address, len, alignment);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = failureCode;
        }

        return status;
    }

    NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode) {
        SIZE_T bytesWritten = 0;
        NTSTATUS status = STATUS_SUCCESS;

        target->Length = source->Length;
        target->MaximumLength = source->MaximumLength;

        if (!target->Buffer) {
            target->Buffer = AllocateMemory<WCHAR*>(static_cast<SIZE_T>(target->Length));

            if (!target->Buffer)
                return STATUS_INSUFFICIENT_RESOURCES;
            memset(target->Buffer, 0, target->Length);
        }

        status = MmCopyVirtualMemory(sourceProcess, source->Buffer, targetProcess,
            target->Buffer, target->Length, (KPROCESSOR_MODE)mode, &bytesWritten);

        if (!NT_SUCCESS(status))
            ExFreePoolWithTag(target->Buffer, DRIVER_TAG);

        return status;
    }

    PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size,
        PULONG foundIndex, ULONG relativeOffset, bool reversed) {
        bool found = false;

        if (pattern == NULL || base == NULL || len == 0 || size == 0)
            return NULL;

        if (!reversed) {
            for (ULONG i = 0; i < size; i++) {
                found = true;

                for (ULONG j = 0; j < len; j++) {
                    if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    if (foundIndex)
                        *foundIndex = i;
                    return (PUCHAR)base + i + relativeOffset;
                }
            }
        }
        else {
            for (int i = (int)size; i >= 0; i--) {
                found = true;

                for (ULONG j = 0; j < len; j++) {
                    if (pattern[j] != wildcard && pattern[j] != *((PCUCHAR)base - i + j)) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    if (foundIndex)
                        *foundIndex = i;
                    return (PUCHAR)base - i - relativeOffset;
                }
            }
        }

        return NULL;
    }
}

// Custom functions

static PVOID(*PsGetProcessSectionBaseAddress)(PEPROCESS process);

UINT64 MemoryHelper::GetBaseAddress(UINT32 PID) {
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsGetProcessSectionBaseAddress");
    PsGetProcessSectionBaseAddress = (decltype(PsGetProcessSectionBaseAddress))MmGetSystemRoutineAddress(&routineName);
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)PID, &process);
    if (status != STATUS_SUCCESS) {
        DbgPrint("[-] Error at GetBaseAddress function, status: %d\n", status);
        return 0;
    }
    PVOID baseAddr = PsGetProcessSectionBaseAddress(process);
    return (UINT64)baseAddr;
}