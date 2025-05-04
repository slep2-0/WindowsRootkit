# Windows Rootkit - By slep2.0

# EDIT: Rootkit now works on windows XP/7/10/11.

# IMPORTANT NOTE, PLEASE READ:
Sorry to not have mentioned this before, but as KPP Exists (Also known as PatchGuard - Kernel Patch Protection), using this Rootkit on a Windows x64 Machine (Vista and onward), will trigger the KPP to bluescreen the machine, 
of course this will not be immediate (or it might be), since KPP does not check every second for the SSDT, DKOM, MSR's, GDT/IDT, and more but those are the main ones, this CAN give you enough time to do your own persistence stuff,
But I would recommend either sticking to user mode programs, or to patch the KPP and the DSE (Driver Signature Enforcement), to use this rootkit effectively and achieve full control, always.

I will not teach you how to patch the KPP and the DSE.

**PLEASE NOTE: If you build the driver and not use the binaries, please check if you want the driver to be loaded reflectively by uncommenting the #define DRL. If you want it to load via service just build without uncommenting.**

This is it for the important note.


This is my most advanced project to date, this is a Kernel-Mode Rootkit, currently it has 4 features.

**REQUIRES WINDOWS DRIVER KIT TO BUILD**

**The features of this project are well documented in comments I have written inside of main.cpp**

Features:

1. Hide from the PsLoadedModuleList (basically the list of all loaded drivers in system)

2. Elevate Process Privileges to nt authority \ system (highest privileges, using the SYSTEM token) (basically the SYSTEM process privileges)

3. Hide processes from system entirely (they are still working, just hidden, like they are not there, poof!)

4. Protect a process, making it so when process terminates, system crashes. (Essentially, becoming a part of the system itself.)

This requires a User-Mode program to interact with the Kernel Mode driver, using IOCTL codes. It is in the folder RootkitClient, build it.

Steps to build:

Install the Windows Driver Kit from the official microsoft website.

Open the .sln file (Solution) in Visual Studio 2022

Build that rootkit!


**DEEPER EXPLANATION**

**Feature 1 - Hide from PsLoadedModuleList**: The way it essentially hides from the list, is placing it so when the list is called, essentially it moves the pointer from itself to skip over it, by Flinking and Blinking (so when it gets to the module, it redirects the pointer behind it to go 2 forwards, and the pointer forwards from it to point to the pointer 2 backwards from it, essentially skipping over itself)

**Feature 2 - Elevate a process using it's PID to NT AUTHORITY \ SYSTEM** - Essentially, the User Mode dispatcher (program), communicates with the driver using IOCTL codes (read in msdn), transferring the PID of the process it wants to elevate. When the driver receives the PID, it initiates a control code, handles the case with the ID of the code, where it does the following: Call a function ElevateProcess that gets the PID, then gets the EPROCESS Structure of the PID's process, and also the EPROCESS structure of the process with PID 4, which is the SYSTEM process, the one with the highest privileges on the system, then it goes to the offest of 0x4b8, which is the Token offset (This was changed after 23H2 versions of windows 11, full list of versions will be below), and basically **copies the token from the SYSTEM one to the process with the PID we gave** (The Token is how Windows knows which privileges the process has).

List of token offsets:


  | *x64 offsets*    | *x86 offsets*        |
  | --------------| ------------------ |
  | 0x0160 (late 5.2) | 0x0150 (3.10)      |
  | 0x0168 (6.0)  | 0x0108 (3.50 to 4.0) |
  | 0x0208 (6.1)  | 0x012C (5.0)        |
  | 0x0348 (6.2 to 6.3) | 0xC8 (5.1 to early 5.2) |
  | 0x0358 (10.0 to 1809) | 0xD8 (late 5.2) |
  | 0x0360 (1903) | 0xE0 (6.0)          |
  | 0x04B8        | 0xF8 (6.1)          |
  |               | 0xEC (6.2 to 6.3)   |
  |               | 0xF4 (10.0 to 1607) |
  |               | 0xFC (1703 to 1903) |
  |               | 0x012C              |


**Feature 3 - Process Hiding** - **Hide a process using his PID, COMPLETE HIDE**: Essentially, the User Mode dispatcher, communicates with the driver IOCTL codes (read in msdn), transferring the PID of the process it wants to hide. When the driver receives the PID, it initiates a control code, handles the case with the ID of the code (namespace), where it does the following: Call a function HideProcess that gets the PID, then gets the current EPROCESS structure, and starts to traverse using the known offset of 0x448 to view the PID of each link in the __EPROCESS structure of all of the processes, essentially doing a while loop that will circle around all of the processes, checking each one for their PID, seeing if they match our process PID we transferred, then flinking and blinking it to essentially hiding it from the list. (so when it gets to the module, it redirects the pointer behind it to go 2 forwards, and the pointer forwards from it to point to the pointer 2 backwards from it, essentially skipping over itself)

**Feature 4 - Process Protection** - **Protect a process using his PID, termination = crash**: *UPDATED* This sets the information of the process (inside of the EPROCESS list) on BreakOnTermination to 1, the kernel checks for every process termination for this flag, and if it is true (1), then the system blue screens with stop code: CRITICAL_PROCESS_DIED, meaning: When you protect a process and it exites (terminates), system crash..

**NEXT FEATURE: Port Hiding**
