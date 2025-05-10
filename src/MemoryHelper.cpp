#include "MemoryHelper.hpp"


PVOID gSharedBuffer = NULL;
PKEVENT gUserEvent = NULL;
HANDLE gSectionHandle = NULL;

VOID MemoryHelper::MSGClient(const char* MSG) {
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

NTSTATUS MemoryHelper::SetupSharedMemory() {
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

void MemoryHelper::CleanupSharedMemory() {
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
