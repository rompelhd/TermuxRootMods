# v1.0.7 Termux Root Modifications - The Way It Should Be By Rompelhd 🥵

- Added an FSU (Fake SU) feature that enables running binaries as root or obtaining a root shell without requiring root privileges. This is achieved using `proot`, providing a secure and flexible solution for simulating root access.

### Usage Examples:

- `fsu fastfetch`  
  Runs the `fastfetch` command with root privileges without needing to be root.

- `fsu`  
  Starts a root shell, allowing you to execute commands as if you were the root user without direct root access.
