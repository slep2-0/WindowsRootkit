# TESTING BRANCH, FEATURES HERE DO NOT WORK, ARE IN IMPLEMENTATION. USE MASTER BRANCH ALWAYS, THIS BRANCH MAY ALSO CORRUPT PC.

**The errors in this branch are in main.cpp of the rootkit itself, I cant seem to implement callbacks to protect a process (protection that will result in Access Denied termination.)

**Found out why - Since I am loading the driver reflectively using KDMapper, PatchGuard will NOT let me register callbacks, (For example, the one im currently using for the Access Denied), registry manipulation is also affected by this as it also uses callbacks, we could modify the list of the registry, but PatchGuard protects this as well, might as well Patch-PatchGuard :)**
  # Windows Rootkit - By slep2.0
