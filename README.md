# MatanelOS Kernel

![DEVELOPMENT](https://img.shields.io/badge/Status-DEVELOPMENT,_STABLE-purple?style=for-the-badge)

MatanelOS is an operating system built from scratch, aiming to provide a fully preemptive, 64-bit kernel environment. Inspired by Windows kernel architecture, MatanelOS incorporates IRQLs, DPCs, paging, dynamic memory management, and a fully-fledged VFS (currently FAT32-backed). Development is driven by curiosity and continuous learning.

This project is currently in early development stages, focusing on core kernel functionality. Tested primarily in QEMU (x64) and built using GCC with C11 standard. The kernel is compiled as an ELF binary and loaded via a UEFI bootloader.

---

## Table of Contents

1. [Supported Features](#supported-features)
2. [Current Development](#current-development)
3. [Build & Test Environment](#build--test-environment)
4. [Roadmap & Future Enhancements](#roadmap--future-enhancements)
5. [Important Notes](#important-notes)

---

## Supported Features

### Core Kernel Features
- **64-bit Long Mode Support:** Full 64-bit addressing with long mode initialization and paging.
- **Preemptive Multitasking:** Kernel supports thread preemption using a priority-based scheduler.
- **IRQLs (Interrupt Request Levels):** Implements IRQLs similar to Windows for fine-grained interrupt control.
- **Deferred Procedure Calls (DPC):** Allows deferring execution to lower IRQLs to prevent high IRQL blocking. Currently supports timer ISR for scheduling.
- **Bugcheck System:** Half implementation – displays bugcheck screens and halts the system. Minidumps coming soon.
- **Paging & Virtual Memory:** Supports `PAGE_PRESENT`, `PAGE_RW`, `PAGE_USER` for kernel/user memory management.
- **Interrupt Handling:** Full exception and interrupt support, including basic keyboard and timer interrupts for scheduling.

### Driver & Hardware
- **AHCI Driver:** Fully implemented for SATA device interaction.
- **Dynamic Heap Memory Allocation:** Kernel fully supports dynamic memory allocation.
- **MTSTATUS Integration:** Kernel functions now return `MTSTATUS` codes, similar to Windows NTSTATUS.

### Filesystem & VFS
- **Virtual File System (VFS):** Modular VFS design with FAT32 as the root mounting point.
- **FAT32 Driver:** Fully implemented with file creation, deletion, directory traversal, and long filename support.

---

## Current Development

- **Userland Support:** Designing a user-mode environment and syscall interface.
- **Enhanced VFS Features:** Future support for multiple filesystems and mounting options.
- **Minidumps:** Will allow capturing kernel state on bugcheck.
- **APIC & SMP Support:** Local APIC and multi-core scheduling integration.
- **Advanced Kernel Services:** Future IPC, timers, and kernel debugging tools.

---

## Build & Test Environment

- **Compiler:** GCC 10.3 with C11 standard
- **Tools:** binutils
- **UEFI Bootloader:** Using [EDK2](https://github.com/tianocore/edk2)
- **Testing:** QEMU x64 virtual environment
- **Kernel Format:** ELF (no objcopy required)

---

## Roadmap & Future Enhancements

- **Minidumps** – Full crash dumps to disk  
- **Userland Programs & Syscalls** – Basic shell and user processes  
- **APIC / SMP** – Multi-core support  
- **Extended VFS Support** – Multiple filesystems and advanced file operations  
- **Advanced DPC / Timer Integration** – More IRQs supported for DPCs  
- **Kernel Debugging Tools** – Runtime assertions, trace logs, and crash analysis  
- **Security & Permissions** – Implement user/kernel memory protections and access control  

---

## Important Notes

MatanelOS is evolving into a fully featured, preemptive OS kernel with modern concepts inspired by Windows. The goal is a testable, extensible system for experimentation, learning, and low-level OS development.

*Use this project responsibly. Intended for educational purposes and testing in controlled virtual environments only.*
