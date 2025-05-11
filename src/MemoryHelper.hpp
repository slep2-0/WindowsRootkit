#pragma once
#include "headers.h"

#define SHARED_MEM_SIZE 512
#define EVENT_NAME L"\\BaseNamedObjects\\MySharedEvent"
#define SECTION_NAME L"\\BaseNamedObjects\\MySharedSection"

namespace MemoryHelper {
	VOID MSGClient(const char* MSG);
	NTSTATUS SetupSharedMemory();
	void CleanupSharedMemory();
}

inline NTSTATUS ProbeAddress(PVOID address, SIZE_T len, ULONG alignment, NTSTATUS failureCode) {
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

template <typename PointerType>
inline PointerType AllocateMemory(size_t size, bool paged = true, bool forceDeprecatedAlloc = false) {
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

inline NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode) {
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