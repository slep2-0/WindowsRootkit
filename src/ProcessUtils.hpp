#pragma once
#include "headers.h"

namespace ProcessUtils {
    int ProtectProcess(UINT32 PID);
    int UnProtectProcess(UINT32 PID);
    int HideDLL(UINT32 PID, const WCHAR* DLLName);
    int HideProcess(UINT32 PID);
    int ElevateProcess(UINT32 PID);
}
