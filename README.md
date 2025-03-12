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
