#pragma once
#include "headers.h"

#define MAX_PIDS 256
#define MAX_TIDS 256

namespace Callbacks {
	// PreOpenProcessOperation shouldn't be exposed on the header file as it is a private function.
	NTSTATUS SetupCallbacks(PDEVICE_OBJECT device_object, UNICODE_STRING symbolic_link);
	OB_PREOP_CALLBACK_STATUS PreOpenProcessOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
	VOID UnregisterCallbacks();
	bool AddProtectionProcess(ULONG PID);
	bool RemoveProtectionProcess(ULONG PID);
}