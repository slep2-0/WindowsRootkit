#pragma once
#include "headers.h"

#define STATUS_SUCCESS_WITH_STEALTH 0x1010101

namespace ProcessUtils {
    NTSTATUS FindPidByName(const wchar_t* processName, ULONG* pid);
    int ProtectProcess(UINT32 PID);
    int UnProtectProcess(UINT32 PID);
    int HideDLL(UINT32 PID, const WCHAR* DLLName);
    int HideProcess(UINT32 PID);
    int ElevateProcess(UINT32 PID);
    NTSTATUS InjectDLL(WCHAR* path, UINT32 PID, bool stealth);
    //NTSTATUS InjectDLLAPC(WCHAR* path, UINT32 PID, bool stealth);
    //int InjectDLLAPC(WCHAR* path, UINT32 PID);
}