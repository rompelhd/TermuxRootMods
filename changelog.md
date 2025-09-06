# v1.0.20 Termux Root Mods - The Way It Should Be, By Rompelhd 🥵

## 🔐 Security Enhancements

- **Password Hashing System Added**  
  A new function `npasshash()` has been implemented to securely store passwords:
  - Uses `PBKDF2` hashing with a fixed salt (`trm_salt_2025`) and 100,000 iterations.
  - Stores hashes in a `.trm_shadow` file with restricted `0600` permissions.
  - Protects credentials by avoiding plaintext storage.

---


## 🧑‍💻 Magisk and sudo.c Fixes

- **`sudo.c` updated to prioritize the new Magisk path:**  
  `"/debug_ramdisk/su"` is now the primary `su` binary location, fixing compatibility with recent Magisk versions.
- **Fixed `sudo su` invocation:**  
  Updated argument list to:  
  ```c
  char *args[8];  // su, [user], --interactive, -c, full_cmd, NULL
  ```

---

## 🛠 Improvements

- 🔧 Minor improvements in:
  - `ChangeTheme()` (better shell handling)
  - `UpdateConfigVariable()` (fallback line creation if missing)
- 🧼 Cleaner configuration management and shell-specific options.

---
