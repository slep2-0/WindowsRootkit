#include "Callbacks.hpp"
PVOID regHandle;
ULONG protectedPidIndex = 0;
ULONG protectedPid[MAX_PIDS] = { 0 };

// Register the pre open process operation callback - which means that everytime a process is opened (handled), it will first come here.
OB_PREOP_CALLBACK_STATUS Callbacks::PreOpenProcessOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (Info->KernelHandle) {
        return OB_PREOP_SUCCESS; // If it's a handle that is called by the kernel driver, we just return success. I might modify this so it also rejects, but IDK if it's possible.
    }
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

NTSTATUS Callbacks::SetupCallbacks(PDEVICE_OBJECT device_object, UNICODE_STRING symbolic_link) {
    NTSTATUS statusCallback;
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

    statusCallback = ObRegisterCallbacks(&reg, &regHandle);
    if (!NT_SUCCESS(statusCallback)) {
        DbgPrint("[!] Failed to register callbacks\n");
        // Clean up resources but allow driver to continue
        DbgPrint("FAILED TO REGISTER CALLBACKS, STATUS=%08X\n", statusCallback);
        IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(device_object);
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("[+] Callbacks registered successfully\n");
    return statusCallback;
}

VOID Callbacks::UnregisterCallbacks() {
    DbgPrint("[++] Unregistering callbacks...\n");
    ObUnRegisterCallbacks(regHandle);
}

bool Callbacks::AddProtectionProcess(ULONG PID) {
    if (protectedPidIndex < MAX_PIDS) {
        protectedPid[protectedPidIndex++] = PID;
        return true;
    }
    else {
        return false;
    }
}

bool Callbacks::RemoveProtectionProcess(ULONG PID) {
    BOOLEAN found = FALSE;
    if (protectedPidIndex > 0) {
        ULONG searchPid = PID;
        ULONG writeIndex = 0;
        for (ULONG readIndex = 0; readIndex < protectedPidIndex; ++readIndex) {
            if (protectedPid[readIndex] != searchPid) {
                // Keep this PID
                protectedPid[writeIndex++] = protectedPid[readIndex];
            }
            else {
                found = TRUE;
                return true;
            }
        }
        protectedPidIndex = writeIndex;
    }
    return false;
}