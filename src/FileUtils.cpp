#include "FileUtils.h"

namespace FileUtils {
	NtfsCallback Callbacks[HOOKED_NTFS_CALLBACKS] = {};
}

FilesList files = {};
FilesList filesDir = {};

// FindFile function is used to search if a file exists in the list of protected files.
bool FileUtils::FindFile(WCHAR* Path) {
	for (ULONG i = 0; i <= files.LastIndex; i++) { // If we break - goes to false.
		if (files.FilesPath[i]) {
			// Truncate the drive letter (C:)
			if (wcslen(files.FilesPath[i]) > 3) {
				if (_wcsnicmp(&files.FilesPath[i][2], Path, wcslen(files.FilesPath[i]) - 2) == 0) {
					return true;
				}
			}
		}
	}
	return false;
}

// AddFile function adds the file's path to the protected list.
bool FileUtils::AddFile(WCHAR* Path) {
	for (ULONG i = 0; i < MAX_FILES; i++) // If we break - goes to false. // MAX_FILES is 256 (max protected files), we check for space.
		if (files.FilesPath[i] == nullptr) { // When we hit a free space, we proceed.
			SIZE_T len = (wcslen(Path) + 1) * sizeof(WCHAR);
			WCHAR* buffer = MemoryHelper::AllocateMemory<WCHAR*>(len);

			// If allocation didn't work, it means there is not enough resources (memory).
			if (!buffer) {
				break;
			}
			errno_t err = wcscpy_s(buffer, len / sizeof(WCHAR), Path); // Copy the buffer into err.

			if (err != 0) { // Not success. (anything that isn't zero in errno_t is not success)
				ExFreePoolWithTag(buffer, DRIVER_TAG);
				break;
			}

			if (i > files.LastIndex) {
				files.LastIndex = i;
			}

			files.FilesPath[i] = buffer;
			files.FilesCount++;

			if (!Callbacks[0].Activated) {
				NTSTATUS status = InstallNTFSHook(IRP_MJ_CREATE);

				if (!NT_SUCCESS(status)) {
					RemoveFile(files.FilesPath[i]);
					break;
				}
			}
			return true;
		}
	return false;
}

// Remove files from the protected list.
bool FileUtils::RemoveFile(WCHAR* path) {
	ULONG newLastIndex = 0;

	for (ULONG i = 0; i <= files.LastIndex; i++) {
		if (files.FilesPath[i] != nullptr) {
			if (_wcsicmp(files.FilesPath[i], path) == 0) {
				ExFreePoolWithTag(files.FilesPath[i], DRIVER_TAG);

				if (i == files.LastIndex)
					files.LastIndex = newLastIndex;
				files.FilesPath[i] = nullptr;
				files.FilesCount--;

				if (GetFilesCount() == 0 && Callbacks[0].Activated) {
					NTSTATUS status = UninstallNTFSHook(IRP_MJ_CREATE);

					if (!NT_SUCCESS(status))
						break;
				}
				return true;
			}
			else
				newLastIndex = i;
		}
	}
	return false;
}

// Clear the whole file list (reset)
void FileUtils::ClearFileList() {

	for (ULONG i = 0; i <= files.LastIndex; i++) {
		if (files.FilesPath[i]) {
			ExFreePoolWithTag(files.FilesPath[i], DRIVER_TAG);
			files.FilesPath[i] = nullptr;
		}
	}

	files.LastIndex = 0;
	files.FilesCount = 0;
}

// Query a file inside of the protected list.
NTSTATUS FileUtils::QueryFile(FileItem* item) {
	NTSTATUS status = STATUS_SUCCESS;
	errno_t err = 0;

	if (item->FileIndex == 0) {
		item->FileIndex = files.FilesCount;

		if (files.FilesCount > 0) {
			err = wcscpy_s(item->FilePath, files.FilesPath[0]);

			if (err != 0)
				status = STATUS_INVALID_USER_BUFFER;
		}
	}
	else if (item->FileIndex > files.LastIndex) {
		status = STATUS_INVALID_PARAMETER;
	}
	else {
		if (files.FilesPath[item->FileIndex] == nullptr)
			return STATUS_INVALID_PARAMETER;

		err = wcscpy_s(item->FilePath, files.FilesPath[item->FileIndex]);

		if (err != 0)
			status = STATUS_INVALID_USER_BUFFER;
	}

	return status;
}

bool FileUtils::FindFileDir(WCHAR* Path) {
	for (ULONG i = 0; i <= filesDir.LastIndex; i++) { // If we break - goes to false.
		if (filesDir.FilesPath[i]) {
			// Truncate the drive letter (C:)
			if (wcslen(filesDir.FilesPath[i]) > 3) {
				if (_wcsnicmp(&filesDir.FilesPath[i][2], Path, wcslen(filesDir.FilesPath[i]) - 2) == 0) {
					return true;
				}
			}
		}
	}
	return false;
}

// AddFile function adds the file's path to the protected list.
bool FileUtils::AddFileDir(WCHAR* Path) {
	for (ULONG i = 0; i < MAX_FILES; i++) // If we break - goes to false. // MAX_FILES is 256 (max protected files), we check for space.
		if (filesDir.FilesPath[i] == nullptr) { // When we hit a free space, we proceed.
			SIZE_T len = (wcslen(Path) + 1) * sizeof(WCHAR);
			WCHAR* buffer = MemoryHelper::AllocateMemory<WCHAR*>(len);

			// If allocation didn't work, it means there is not enough resources (memory).
			if (!buffer) {
				break;
			}
			errno_t err = wcscpy_s(buffer, len / sizeof(WCHAR), Path); // Copy the buffer into err.

			if (err != 0) { // Not success. (anything that isn't zero in errno_t is not success)
				ExFreePoolWithTag(buffer, DRIVER_TAG);
				break;
			}

			if (i > filesDir.LastIndex) {
				filesDir.LastIndex = i;
			}

			filesDir.FilesPath[i] = buffer;
			filesDir.FilesCount++;

			if (!Callbacks[1].Activated) {
				NTSTATUS status = InstallNTFSHook(IRP_MJ_DIRECTORY_CONTROL);

				if (!NT_SUCCESS(status)) {
					RemoveFile(filesDir.FilesPath[i]);
					break;
				}
			}
			return true;
		}
	return false;
}

// Remove files from the protected list.
bool FileUtils::RemoveFileDir(WCHAR* path) {
	ULONG newLastIndex = 0;

	for (ULONG i = 0; i <= filesDir.LastIndex; i++) {
		if (filesDir.FilesPath[i] != nullptr) {
			if (_wcsicmp(filesDir.FilesPath[i], path) == 0) {
				ExFreePoolWithTag(filesDir.FilesPath[i], DRIVER_TAG);

				if (i == filesDir.LastIndex)
					filesDir.LastIndex = newLastIndex;
				filesDir.FilesPath[i] = nullptr;
				filesDir.FilesCount--;

				if (GetFilesCount() == 0 && Callbacks[1].Activated) {
					NTSTATUS status = UninstallNTFSHook(IRP_MJ_DIRECTORY_CONTROL);

					if (!NT_SUCCESS(status))
						break;
				}
				return true;
			}
			else
				newLastIndex = i;
		}
	}
	return false;
}

// Clear the whole file list (reset)
void FileUtils::ClearFileListDir() {

	for (ULONG i = 0; i <= filesDir.LastIndex; i++) {
		if (filesDir.FilesPath[i]) {
			ExFreePoolWithTag(filesDir.FilesPath[i], DRIVER_TAG);
			filesDir.FilesPath[i] = nullptr;
		}
	}

	filesDir.LastIndex = 0;
	filesDir.FilesCount = 0;
}

/*NTSTATUS FileUtils::HookedNTFSIrpCreateDirectory(
	PDEVICE_OBJECT DeviceObject,
	PIRP           Irp
) {
	// 1) Grab the current stack location once
	PIO_STACK_LOCATION  stack = IoGetCurrentIrpStackLocation(Irp);
	bool isQueryDir =
		stack->MajorFunction == IRP_MJ_DIRECTORY_CONTROL &&
		stack->MinorFunction == IRP_MN_QUERY_DIRECTORY;

	// 2) Call the REAL NTFS routine you saved when you hooked it:
	auto OriginalNtfsDirectory =
		(tNtfsIrpFunction)GetNtfsCallback(1).Address;
	NTSTATUS rc = OriginalNtfsDirectory(DeviceObject, Irp);

	// 3) If it was a QueryDirectory and it succeeded, splice out “a.txt”
	if (isQueryDir && NT_SUCCESS(rc)) {
		PUCHAR base = (PUCHAR)Irp->UserBuffer;
		PUCHAR end = base + Irp->IoStatus.Information;
		auto  entry = (PFILE_BOTH_DIR_INFORMATION)base;
		PFILE_BOTH_DIR_INFORMATION prev = nullptr;

		while ((PUCHAR)entry < end) {
			WCHAR* name = (WCHAR*)entry->FileName;
			bool match = wcscmp(name, L"a.txt") == 0;

			PUCHAR nextPtr = entry->NextEntryOffset
				? (PUCHAR)entry + entry->NextEntryOffset
				: end;

			if (match) {
				// splice it out
				if (prev) {
					prev->NextEntryOffset += entry->NextEntryOffset;
				}
				else {
					SIZE_T moveLen = end - nextPtr;
					RtlMoveMemory(entry, nextPtr, moveLen);
					RtlZeroMemory(base + moveLen,
						(ULONG)(end - (base + moveLen)));
				}
				end -= entry->NextEntryOffset;
				Irp->IoStatus.Information =
					(ULONG)(end - base);
				stack->Parameters.QueryDirectory.Length =
					(ULONG)(end - base);


				entry = prev
					? (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)prev
						+ prev->NextEntryOffset)
					: (PFILE_BOTH_DIR_INFORMATION)base;
				continue;
			}

			if (!entry->NextEntryOffset)
				break;
			prev = entry;
			entry = (PFILE_BOTH_DIR_INFORMATION)nextPtr;
		}
	}

	// 4) Return the same status NTFS gave us
	return rc;
}
*/
NTSTATUS FileUtils::HookedNTFSIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	auto stack = IoGetCurrentIrpStackLocation(Irp);
	UNICODE_STRING fullPath = { 0 };
	KIRQL prevIrql = 0;
	NTSTATUS status = STATUS_SUCCESS;

	do {
		// Validations.
		if (!stack || !stack->FileObject) {
			break;
		}

		if (stack->FileObject->FileName.Length == 0 || !stack->FileObject->FileName.Buffer) {
			break;
		}

		// Probe the address to see if it's even a valid User-Mode address, if we don't do this and it's invalid, a BSOD will happen because of access violations.
		status = MemoryHelper::ProbeAddress(stack->FileObject->FileName.Buffer, stack->FileObject->FileName.Length, sizeof(WCHAR*), STATUS_NOT_FOUND);

		if (!NT_SUCCESS(status)) {
			break;
		}

		// Acquiring spinlock to prevent other drivers from accessing the files.
		KeAcquireSpinLock(&stack->FileObject->IrpListLock, &prevIrql);
		KeLowerIrql(prevIrql); // lowering IRQL for CopyUnicodeString

		status = MemoryHelper::CopyUnicodeString(PsGetCurrentProcess(), &stack->FileObject->FileName, PsGetCurrentProcess(), &fullPath, KernelMode);

		// If no buffer, or the function didn't give a success status code, we abort.
		if (!NT_SUCCESS(status) || !fullPath.Buffer) {
			break;
		}

		// Raising IRQL Back.
		KeRaiseIrql(DISPATCH_LEVEL, &prevIrql);
		// Release the spinlock for file modifications.
		KeReleaseSpinLock(&stack->FileObject->IrpListLock, prevIrql);

		// If intercepting the IRP, and we find our file that has been added to the list, we deny access for deletion.
		if (FileUtils::FindFile(fullPath.Buffer)) {
			ExFreePoolWithTag(fullPath.Buffer, DRIVER_TAG);
			// Deny access, flip the status to ACCESS_DENIED.
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
			return STATUS_SUCCESS;
		}
	} while (false);

	if (fullPath.Buffer) {
		// Free the memory of the buffer.
		ExFreePoolWithTag(fullPath.Buffer, DRIVER_TAG);
	}
	// Return back to the original function with the modified IRP.
	return ((tNtfsIrpFunction)FileUtils::GetNtfsCallback(0).Address)(DeviceObject, Irp);
}

// Installing the NTFS Hook - Replace the JMP instruction with the function of the NTFS driver to ours, then returning back to the original with the modified parameters - if modified.
NTSTATUS FileUtils::InstallNTFSHook(int irpMjFunction) {
	// Set the driver name
	UNICODE_STRING driverName;
	// Driver object of the NTFS Driver.
	PDRIVER_OBJECT driverObject;
	// Default - Success.
	NTSTATUS status = STATUS_SUCCESS;
	// We use unicode strings because that's the only way the Kernel understands string, via unicode.
	RtlInitUnicodeString(&driverName, L"\\FileSystem\\NTFS");
	// Now that we have set the driver name, we obtain the driver object via refercing the object, the kernel will handle it for us.
	status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&driverObject);

	if (!NT_SUCCESS(status)) {
		return status; // Failure - abort.
	}

	switch (irpMjFunction) { // Switch on MJ function we want to hook.
		// More will be supported.
	case IRP_MJ_CREATE:
		// Set the address of the Hook.
		Callbacks[0].Address = (PVOID)InterlockedExchange64((LONG64*)&driverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)HookedNTFSIrpCreate);
		// Set to active.
		Callbacks[0].Activated = true;
		break;
		/*
	case IRP_MJ_DIRECTORY_CONTROL:
		//Callbacks[1].Address = (PVOID)InterlockedExchange64((LONG64*)&driverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL], (LONG64)HookedNTFSIrpCreateDirectory);
		Callbacks[1].Activated = true;
		//DbgPrint("ACTIVATED NTFS HOOK DIR.\n");
		break;
		*/
	default:
		status = STATUS_NOT_SUPPORTED;
	}

	// Cleanup - we don't want memory leaks.
	ObDereferenceObject(driverObject);
	return status;
}

// Uninstalling the NTFS Hook incase we want to disable protection on files.
NTSTATUS FileUtils::UninstallNTFSHook(int irpMjFunction) {
	UNICODE_STRING driverName;
	PDRIVER_OBJECT driverObject;
	NTSTATUS status = STATUS_SUCCESS;
	RtlInitUnicodeString(&driverName, L"\\FileSystem\\NTFS");

	status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&driverObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	switch (irpMjFunction) {
	case IRP_MJ_CREATE:
		InterlockedExchange64((LONG64*)&driverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)Callbacks[0].Address);
		Callbacks[0].Address = nullptr;
		Callbacks[0].Activated = false;
		break;
	case IRP_MJ_DIRECTORY_CONTROL:
		InterlockedExchange64((LONG64*)&driverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL], (LONG64)Callbacks[1].Address);
		Callbacks[1].Address = nullptr;
		Callbacks[1].Activated = false;
		break;
	default:
		status = STATUS_NOT_SUPPORTED;
	}

	ObDereferenceObject(driverObject);
	return status;
}