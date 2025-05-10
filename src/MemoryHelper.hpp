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