# v1.0.8 Termux Root Mods - The Way It Should Be, By Rompelhd 🥵

The scripts for x86_64 architecture were previously stored in a separate directory under system/etc/arch/x86_64. However, since the code for x86_64, ARM, and ARM64 has been unified into the same C++ source code (compiled for the respective architectures), the need for a dedicated directory for x86_64 architecture has become redundant. All the scripts (like temps and servistatus) are now compiled for multiple architectures, making the separate storage directory unnecessary.

Therefore, the system/etc/arch/x86_64 directory is being deleted to streamline the system and remove obsolete structure.
