#include "KernelUtils.h"
#include "MemoryHelper.h"
#include "ProcessUtils.h"

PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdtAddress;

NTSTATUS KernelUtils::GetSSDT() {
	// Basic init.
	ULONG infoSize = 0;
	PVOID SSDTRelativeAddress = nullptr;
	PVOID ntoskrnlBase = nullptr;
	PRTL_PROCESS_MODULES info = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	// Byte pattern of the current SSDT, note: this may change within windows versions, I don't see any special 00 bytes so this is probably an exact copy.
	UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

	// Get the NTOSKRNL base.
	// First get the size of current SystemModuleInformation.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info) {
			ExFreePoolWithTag(info, DRIVER_TAG);
		}
		info = MemoryHelper::AllocateMemory<PRTL_PROCESS_MODULES>(infoSize);

		if (!info) {
			// Not enough space to allocate memory.
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (status != STATUS_SUCCESS || !info) {
		return status;
	}

	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		// Get the pointer to NtCreateFile and from that iterate over all of the modules.
		if (NtCreateFile >= modules[i].ImageBase && static_cast<PVOID>(static_cast<PUCHAR>(modules[i].ImageBase) + modules[i].ImageSize) > NtCreateFile) {
			// if we are above a module base of slot i, we passed NtCreateFile.
			// Remember, that not every base is ntoskrnl base, this is why we iterate over until we find a known function base like NtCreateFile that does reside in the ntoskrnl base.
			ntoskrnlBase = modules[i].ImageBase;
			break;
		}
	}

	if (!ntoskrnlBase) {
		// Couldn't find the base, return.
		ExFreePoolWithTag(info, DRIVER_TAG);
		return STATUS_NOT_FOUND;
	}

	// Get the DOS Header of ntoskrnl.
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlBase;

	// we will probably do this a lot of times, so i'll just create a lambda.
	auto freeinfo = [info]() -> void {
		ExFreePoolWithTag(info, DRIVER_TAG);
	};

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		//invalid dos signature.
		freeinfo();
		return STATUS_INVALID_SIGNATURE;
	}

	PFULL_IMAGE_NT_HEADERS ntHeader = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
		//invalid nt signature.
		freeinfo();
		return STATUS_INVALID_SIGNATURE;
	}

	PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHeader + 1);

	// iterate over all sections (.bss .data) until we find .text
	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeader->FileHeader.NumberOfSections; section++) {
		if (strcmp((const char*)section->Name, ".text") == 0) {
			// wildcard is 0xCC - means that in every SSDT version those bytes are subject to change.
			SSDTRelativeAddress = MemoryHelper::FindPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntoskrnlBase + section->VirtualAddress, section->Misc.VirtualSize, NULL, 0);

			if (SSDTRelativeAddress) {
				status = STATUS_SUCCESS;
				ssdtAddress = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)SSDTRelativeAddress + *(PULONG)((PUCHAR)SSDTRelativeAddress + 3) + 7);
				isSSDTGotten = true;
				break;
			}
		}
	}

	freeinfo();
	return status;
}

PVOID KernelUtils::GetSSDTFunctionAddress(const char* funcName) {
	if (!isSSDTGotten) {
		GetSSDT();
	}
	KAPC_STATE state;
	PEPROCESS csrssProcess = nullptr;
	PVOID funcAddr = nullptr;
	ULONG index = 0;
	UCHAR syscall = 0;
	ULONG csrssPid = 0;
	// The reason we are finding the csrss pid for this, is that the csrss has ntdll.dll loaded in, with all of the syscalls in it, so instead of using hardcoded syscalls, we use the latest ones available in the system.
	NTSTATUS status = ProcessUtils::FindPidByName(L"csrss.exe", &csrssPid);

	if (status != STATUS_SUCCESS) {
		return funcAddr;
	}

	status = PsLookupProcessByProcessId(UlongToHandle(csrssPid), &csrssProcess);

	if (status != STATUS_SUCCESS) {
		return funcAddr;
	}

	// Attach to the process stack.
	KeStackAttachProcess(csrssProcess, &state);
	PVOID ntdllBase = MemoryHelper::GetModuleBase(csrssProcess, L"ntdll.dll");

	if (!ntdllBase) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(csrssProcess);
		return funcAddr;
	}
	// Function names in ntdll (Nt) are the same in the SSDT.
	PVOID ntdllFunctionAddress = MemoryHelper::GetProcAddress(ntdllBase, funcName);

	if (!ntdllFunctionAddress) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(csrssProcess);
		return funcAddr;
	}

	// Search for the SYSCALL inside of ntdll.
	while (((PUCHAR)ntdllFunctionAddress)[index] != RETURN_OPCODE) {
		// If inside of the function address we found the MOV_EAX_OPCODE, this means that in the next byte the syscall number is present.
		if (((PUCHAR)ntdllFunctionAddress)[index] == MOV_EAX_OPCODE) {
			syscall = ((PUCHAR)ntdllFunctionAddress)[index + 1];
		}
		index++;
	}
	KeUnstackDetachProcess(&state);

	if (syscall != 0) {
		// So if the syscall is found, in the SSDT we go into the slot the syscall is present, and bit shift 4 to the right (SHR), and thats the relative address from the base, then if we add the base this is the absolute address in ntoskrnl.
		funcAddr = (PUCHAR)ssdtAddress->ServiceTableBase + (((PULONG)ssdtAddress->ServiceTableBase)[syscall] >> 4);
	}

	ObDereferenceObject(csrssProcess);
	return funcAddr;
}

void DisableWriteProtection() {
	__writecr0(__readcr0() & (~0x10000));
	_disable(); // disables interrupts
}

void EnableWriteProtection() {
	_enable();
	__writecr0(__readcr0() | 0x10000);
}

typedef NTSTATUS(*NtCreateFilePrototype)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength);

NtCreateFilePrototype OrigNtCreateFile = NULL;
/*
NTSTATUS NtCreateFileHooked(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes, if this is ever used, remove the _In_ or _Out_ or anything before the actual typedefs.
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{
	DbgPrint(
		"DesiredAccess=0x%X, ObjectAttributes=0x%p, IoStatusBlock=0x%p, AllocationSize=0x%p, "
		"FileAttributes=0x%X, ShareAccess=0x%X, CreateDisposition=0x%X, CreateOptions=0x%X, "
		"EaBuffer=0x%p, EaLength=0x%X\n",
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	// Call original function and return its status
	return OrigNtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}
*/
// DOESN'T WORK.
NTSTATUS HookSSDTFunction(const char* funcName, PVOID newFunc) {
	if (!isSSDTGotten) {
		KernelUtils::GetSSDT();
	}
	KAPC_STATE state;
	PEPROCESS csrssProcess = nullptr;
	ULONG index = 0;
	UCHAR syscall = 0;
	ULONG csrssPid = 0;
	// The reason we are finding the csrss pid for this, is that the csrss has ntdll.dll loaded in, with all of the syscalls in it, so instead of using hardcoded syscalls, we use the latest ones available in the system.
	NTSTATUS status = ProcessUtils::FindPidByName(L"csrss.exe", &csrssPid);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	status = PsLookupProcessByProcessId(UlongToHandle(csrssPid), &csrssProcess);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	// Attach to the process stack.
	KeStackAttachProcess(csrssProcess, &state);
	PVOID ntdllBase = MemoryHelper::GetModuleBase(csrssProcess, L"ntdll.dll");

	if (!ntdllBase) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(csrssProcess);
		return STATUS_ADDRESS_NOT_ASSOCIATED;
	}
	// Function names in ntdll (Nt) are the same in the SSDT.
	PVOID ntdllFunctionAddress = MemoryHelper::GetProcAddress(ntdllBase, funcName);

	if (!ntdllFunctionAddress) {
		KeUnstackDetachProcess(&state);
		ObDereferenceObject(csrssProcess);
		return STATUS_ADDRESS_NOT_ASSOCIATED;
	}

	// Search for the SYSCALL inside of ntdll.
	while (((PUCHAR)ntdllFunctionAddress)[index] != RETURN_OPCODE) {
		// If inside of the function address we found the MOV_EAX_OPCODE, this means that in the next byte the syscall number is present.
		if (((PUCHAR)ntdllFunctionAddress)[index] == MOV_EAX_OPCODE) {
			syscall = ((PUCHAR)ntdllFunctionAddress)[index + 1];
		}
		index++;
	}
	KeUnstackDetachProcess(&state);

	if (syscall != 0) {
		// Decode original function pointer
		ULONG originalEntry = ((PULONG)ssdtAddress->ServiceTableBase)[syscall];
		PVOID originalFunction = (PVOID)((PUCHAR)ssdtAddress->ServiceTableBase + (originalEntry >> 4));
		OrigNtCreateFile = (NtCreateFilePrototype)originalFunction;

		// Calculate offset of your hook function from ServiceTableBase
		ULONG_PTR hookOffset = (ULONG_PTR)newFunc - (ULONG_PTR)ssdtAddress->ServiceTableBase;

		// Encode hook offset (shift left 4 bits)
		ULONG newEntry = (ULONG)(hookOffset << 4);

		DisableWriteProtection();
		InterlockedExchange((volatile LONG*)&((PULONG)ssdtAddress->ServiceTableBase)[syscall], (LONG)newEntry);
		EnableWriteProtection();
	}

	ObDereferenceObject(csrssProcess);
	return STATUS_SUCCESS;
}