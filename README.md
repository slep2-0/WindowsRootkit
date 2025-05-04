# Windows Kernel-Mode Rootkit (slep2.0)

This project implements a Windows kernel-mode rootkit compatible with Windows XP, 7, 10, and 11. It provides four core features for process and driver manipulation. Use this only in controlled, ethical penetration-testing environments (e.g., virtual machines).

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Important Considerations](#important-considerations)
3. [Build Instructions](#build-instructions)
4. [Usage](#usage)
5. [Feature Overview](#feature-overview)

   * [1. Module Hiding](#1-module-hiding)
   * [2. Privilege Elevation](#2-privilege-elevation)
   * [3. Process Hiding](#3-process-hiding)
   * [4. Process Protection](#4-process-protection)
6. [Reflective vs. Service Loading](#reflective-vs-service-loading)
7. [Future Enhancements](#future-enhancements)

---

## Prerequisites

* **Windows Driver Kit (WDK)**
* **Visual Studio 2022**
* **Administrator privileges** on the target system
* **User-mode client application** (provided in `RootkitClient`)

---

## Important Considerations

* **Kernel Patch Protection (KPP / PatchGuard):**

  * On 64-bit Windows Vista and later, PatchGuard may detect modifications to SSDT, DKOM, MSRs, GDT/IDT, etc., and trigger a bug check (blue screen).
  * Detection timing is nondeterministic; you may have a window of opportunity to establish persistence before a crash occurs.
  * For sustained stealth, you must patch PatchGuard and disable Driver Signature Enforcement (DSE). **This repository does *not* include KPP or DSE patches.**

---

## Build Instructions

1. **Install WDK & Visual Studio**

   * Download and install the latest Windows Driver Kit from Microsoft.
   * Install Visual Studio 2022 with C++ development tools.

2. **Open Solution**

   * Launch Visual Studio and open `RootkitDriver.sln`.

3. **Configure Driver-Loading Mode**

   * By default, the driver loads via a service.
   * To enable reflective loading (in-memory), uncomment `#define DRL` in `main.cpp`.

4. **Build**

   * Select the target architecture (x86 or x64) and build the solution.
   * The driver binary (`.sys`) and client executable will be generated.

---

## Usage

1. **Install & Start Driver**
  
  **Note: Must use the service version of the driver, by uncommenting #define DRL or using the binary.**
   ```powershell
   sc create RootkitDriver type= kernel binPath= "<path>\RootkitDriverService.sys" start= system
   sc start RootkitDriver
   ```

2. **Run User-Mode Client**

   * Build the client in the `RootkitClient` folder.
   * Use its command-line interface to send IOCTL codes and target process IDs:

     ```cmd
     RootkitClient.exe > Choose from The Menu.
     ```

---

## Feature Overview

### 1. Module Hiding

Removes the driver from the `PsLoadedModuleList` by patching the doubly linked list pointers (FLINK/BLINK) to skip the driver entry.

### 2. Privilege Elevation

Replaces the token of a target process with the token of the `SYSTEM` process (PID 4), granting NT AUTHORITY\SYSTEM privileges.

* **Token offset:** 0x4B8 (may vary across Windows versions - accounted for that in code).

### 3. Process Hiding

Traverses the active process list and unlinks the target process from the `__EPROCESS` list, making it invisible to enumeration.

* **EPROCESS list offset:** 0x448. (varies across Windows versions - accounted for that in code)

### 4. Process Protection

Sets the `BreakOnTermination` flag in the target process’s `__EPROCESS` structure.

* If the protected process exits or is terminated, the system will bug check with **CRITICAL\_PROCESS\_DIED**.

---

## Reflective vs. Service Loading

* **Service Loading (default):** Loads driver via SCM (Service Control Manager).
* **Reflective Loading:** Loads driver into memory without SCM.

  * Enable by uncommenting `#define DRL` in `main.cpp`.

---

## Future Enhancements

* **Port Hiding:** Conceal network ports in TCP/IP stack tables.
* **Extended DKOM:** Modify additional kernel structures for enhanced stealth.

---

*Use this rootkit code responsibly. Always ensure you have explicit authorization before testing on any system.*
