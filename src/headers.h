#pragma once
#define VALID_USERMODE_MEMORY(MemAddress)(MemAddress > 0 && MemAddress < 0x7FFFFFFFFFFFFFFF)
#define VALID_KERNELMODE_MEMORY(MemAddress)(MemAddress > 0x8000000000000000 && MemAddress < 0xFFFFFFFFFFFFFFFF)


#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED   0x00000001
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

#define MAX_PATH 2056
#define DRIVER_TAG 'tooR'

#include <intrin.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "WindowsTypes.hpp"
#include "MemoryHelper.h"