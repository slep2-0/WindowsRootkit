#pragma once
#include <ntifs.h>
#include <ntddk.h>
//#include <winioctl.h>  // Add this at the top with other includes
// Ensure proper alignment for structures
#pragma pack(push, 8)

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#pragma pack(pop)

// Add memory barrier macros for synchronization
#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _mm_mfence()
#endif

// Add IRQL checking macros
#define IS_VALID_IRQL(irql) (KeGetCurrentIrql() <= (irql))
