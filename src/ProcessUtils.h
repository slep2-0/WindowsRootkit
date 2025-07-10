#pragma once
#include "headers.h"
namespace ProcessUtils {
    int ProtectProcess(UINT32 PID);
    int UnProtectProcess(UINT32 PID);
    int HideDLL(UINT32 PID, const WCHAR* DLLName);
    int HideProcess(UINT32 PID);
    int ElevateProcess(UINT32 PID);
    int InjectDLL(WCHAR* path, UINT32 PID/*, bool stealth */ );
    //int InjectDLLAPC(WCHAR* path, UINT32 PID);
	NTSTATUS FindPidByName(const wchar_t* processName, ULONG* pid);
}