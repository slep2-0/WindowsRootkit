#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "WindowsTypes.hpp"
#define MAX_PATH 2056
#define DRIVER_TAG 'tooR'

#define VALID_USERMODE_MEMORY(MemAddress)(MemAddress > 0 && MemAddress < 0x7FFFFFFFFFFFFFFF)
#define VALID_KERNELMODE_MEMORY(MemAddress)(MemAddress > 0x8000000000000000 && MemAddress < 0xFFFFFFFFFFFFFFFF)
