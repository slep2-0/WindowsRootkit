#pragma once

// Memory validation macros
#define VALID_USERMODE_MEMORY(addr) ((addr) > 0 && (addr) < 0x7FFFFFFFFFFFFFFF)
#define VALID_KERNELMODE_MEMORY(addr) ((addr) > 0x8000000000000000 && (addr) < 0xFFFFFFFFFFFFFFFF)

// Thread creation flags
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED   0x00000001
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

// Driver-specific tag
#ifdef DRIVER_TAG
#undef DRIVER_TAG
#endif
#define DRIVER_TAG 'pelS'

// Custom status codes (no trailing semicolon)
#define STATUS_INVALID_GIVEN_ADDRESS 0x00069420
#define STATUS_INVALID_BASE 0xFF6969FF

// Tell Detours this is kernel mode
#define DETOURS_KERNEL

// Core WDK headers (must come before any PE/Detours headers)
#include <ntifs.h>
#include <ntimage.h>    // IMAGE_* definitions
#include <ntstrsafe.h>
#include <intrin.h>
#include <minwindef.h>

// Detours kernel-mode library
#include "../../includes/detours.h"

// Project Headers.
#include "WindowsTypes.hpp"
#include "MemoryHelper.h"
#include "KernelUtils.h"
#include "HookingUtils.h"