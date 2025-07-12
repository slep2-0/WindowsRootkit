#pragma once
#include "headers.h"

static bool isSSDTGotten = false;

namespace KernelUtils {
	NTSTATUS GetSSDT();
	PVOID GetSSDTFunctionAddress(const char* funcName);
	//NTSTATUS HookSSDTFunction(const char* funcName, PVOID newFunc);
	//NTSTATUS HookNtCreateFile();
}