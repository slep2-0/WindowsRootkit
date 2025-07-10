#pragma once
#include "headers.h"

#define MAX_FILES 256
#define HOOKED_NTFS_CALLBACKS 2

// Structs.
struct ProtectedFile {
	WCHAR* FilePath;
	bool Protect;
};

struct FileItem {
	ULONG FileIndex;
	WCHAR FilePath[MAX_PATH];
};

struct FilesList {
	ULONG LastIndex;
	ULONG FilesCount;
	WCHAR* FilesPath[MAX_FILES];
};

struct NtfsCallback {
	PVOID Address;
	bool Activated;
};

extern FilesList files;
extern FilesList filesDir;

namespace FileUtils {
	// Currently 1 callback (1), so we use Callbacks[0] to specify the first entry.
	extern NtfsCallback Callbacks[HOOKED_NTFS_CALLBACKS];
	bool FindFile(WCHAR* Path);
	bool AddFile(WCHAR* path);
	bool RemoveFile(WCHAR* path);
	bool FindFileDir(WCHAR* Path);
	bool AddFileDir(WCHAR* path);
	bool RemoveFileDir(WCHAR* path);
	void ClearFileList();
	void ClearFileListDir();
	//NTSTATUS HookedNTFSIrpCreateDirectory(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS HookedNTFSIrpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS InstallNTFSHook(int irpMjFunction);
	NTSTATUS UninstallNTFSHook(int irpMjFunction);
	NTSTATUS QueryFile(FileItem* item);
	inline ULONG GetFilesCount() { return files.FilesCount; }
	inline NtfsCallback GetNtfsCallback(ULONG index) {
		return Callbacks[index];
	}
}