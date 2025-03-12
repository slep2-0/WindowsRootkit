# Windows Rootkit - By slep2.0

This is my most advanced project to date, this is a Kernel-Mode Rootkit, currently it has 2 features (as it is day 1 of coding it).

**REQUIRES WINDOWS DRIVER KIT TO BUILD**

Features:

1. Hide from the PsLoadedModuleList (basically the list of all loaded drivers in system)

2. Elevate Process Privileges (WORKS UNTIL 22H2 VERSIONS OF WIN10+11, WILL UPDATE LATER)

This requires a User-Mode program to interact with the Kernel Mode driver, using IOCTL codes, the user mode program will be in a different repository, bcz idk how to use git.

Steps to build:

Install the Windows Driver Kit from the official microsoft website.

Open the .sln file (Solution) in Visual Studio 2022

Build that rootkit!


**DEEPER EXPLANATION**

**Feature 1 - Hide from PsLoadedModuleList**: The way it essentially hides from the list, is placing it so when the list is called, essentially it moves the pointer from itself to skip over it, by Flinking and Blinking (so when it gets to the module, it redirects the pointer behind to go 1 forwards from it, essentially skipping over itself)

**Feature 2 - Elevate a process using it's PID to NT AUTHORITY \ SYSTEM **- Essentially, the User Mode dispatcher (program), communicates with the driver using IOCTL codes (read in msdn), transferring the PID of the process it wants to elevate. When the driver receives the PID, it initiates a control code, handles the case with the ID of the code, where it does the following: Call a function ElevateProcess that gets the PID, then gets the EPROCESS Structure of the PID's process, and also the EPROCESS structure of the process with PID 4, which is the SYSTEM process, the one with the highest privileges on the system, then it goes to the offest of 0x4b8, which is the Token offset (This was changed after 22H2 versions of windows 10 and 11, full list of versions will be below), and basically **copies the token from the SYSTEM one to the process with the PID we gave** (The Token is how Windows knows which privileges the process has).

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

*NEXT FEATURE: Process Hiding. (Transfer a PID to hide from the process list, entirely) (Will be worked on tomorrow, the 13/03/2025, read DD/MM/YY)*
