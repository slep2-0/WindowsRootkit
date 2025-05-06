#pragma once
#include <ntifs.h>
#include <ntddk.h>
//#include <winioctl.h>  // Add this at the top with other includes
// Ensure proper alignment for structures
#pragma pack(push, 8)
#pragma pack(pop)

// Add memory barrier macros for synchronization
#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _mm_mfence()
#endif

// Add IRQL checking macros
#define IS_VALID_IRQL(irql) (KeGetCurrentIrql() <= (irql))
