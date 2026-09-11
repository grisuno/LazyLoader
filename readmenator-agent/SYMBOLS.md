# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `AESencrypt` | function | `aes.py:7` | `def AESencrypt(plaintext, key)` |
| `dropFile` | function | `aes.py:15` | `def dropFile(key, ciphertext)` |
| `12` | type_alias | `main.c:56` | `typedef struct _BASE_RELOCATION_ENTRY { WORD Offset : 12;` |
| `CloseHandle` | function | `main.c:184` | `CloseHandle(pi.hThread);` |
| `DATA` | struct | `main.c:62` | `` |
| `DecryptAES` | function | `main.c:526` | `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)` |
| `ExitProcess` | function | `main.c:192` | `ExitProcess(0);` |
| `ExitThread` | function | `main.c:209` | `ExitThread(0);` |
| `GetData` | function | `main.c:559` | `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)` |
| `GetNTHeaders` | function | `main.c:270` | `char* GetNTHeaders(char* pe_buffer)` |
| `GetPEDirectory` | function | `main.c:282` | `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)` |
| `LocalFree` | function | `main.c:238` | `LocalFree(poi_masqArgvW);` |
| `MultiByteToWideChar` | function | `main.c:221` | `MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);` |
| `NTSTATUS` | type_alias | `main.c:54` | `typedef LONG NTSTATUS;` |
| `NTSTATUS` | function | `main.c:390` | `typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);` |
| `NT_SUCCESS` | macro | `main.c:46` | `#define NT_SUCCESS(Status)` |
| `NtCurrentProcess` | macro | `main.c:50` | `#define NtCurrentProcess()` |
| `NtCurrentThread` | macro | `main.c:48` | `#define NtCurrentThread()` |
| `NtUnmapViewOfSection` | function | `main.c:393` | `NtUnmapViewOfSection(NtCurrentProcess(), preferAddr);` |
| `PELoader` | function | `main.c:373` | `void PELoader(char* data, DWORD datasize)` |
| `RegCloseKey` | function | `main.c:124` | `RegCloseKey(hKey);` |
| `RegDeleteValueA` | function | `main.c:155` | `RegDeleteValueA(hKey, "SystemMaintenance");` |
| `RepairIAT` | function | `main.c:292` | `BOOL RepairIAT(PVOID modulePtr)` |
| `RunPE` | function | `main.c:367` | `DWORD WINAPI RunPE(LPVOID lpParameter)` |
| `Sleep` | function | `main.c:723` | `Sleep(3000);` |
| `TerminateProcess` | function | `main.c:461` | `TerminateProcess(pi.hProcess, 0);` |
| `Unhook` | function | `main.c:490` | `BOOL Unhook(LPVOID cleanNtdll)` |
| `VirtualFree` | function | `main.c:413` | `VirtualFree(pImageBase, 0, MEM_RELEASE);` |
| `WaitForSingleObject` | function | `main.c:439` | `WaitForSingleObject(hThread, INFINITE);` |
| `WideCharToMultiByte` | function | `main.c:569` | `WideCharToMultiByte(CP_UTF8, 0, wresource, -1, resourceA, sizeof(resourceA)-1, NULL, NULL);` |
| `WinHttpCloseHandle` | function | `main.c:582` | `WinHttpCloseHandle(hSession);` |
| `ZeroMemory` | function | `main.c:617` | `ZeroMemory(pszOutBuffer, dwSize + 1);` |
| `_BASE_RELOCATION_ENTRY` | struct | `main.c:57` | `` |
| `_CRT_RAND_S` | macro | `main.c:35` | `#define _CRT_RAND_S` |
| `_CRT_SECURE_NO_WARNINGS` | macro | `main.c:53` | `#define _CRT_SECURE_NO_WARNINGS` |
| `_stricmp` | function | `main.c:347` | `_stricmp(func_name, "exit") == 0 \|\|
                    _stricmp(func_name, "_Exit") == 0 \|\|
    ...` |
| `anti_analysis` | function | `main.c:115` | `BOOL anti_analysis()` |
| `entryPoint` | function | `main.c:370` | `entryPoint();` |
| `ep` | function | `main.c:444` | `ep();` |
| `fflush` | function | `main.c:142` | `fflush(stdout);` |
| `free` | function | `main.c:225` | `free(sz_masqCmd_Widh);` |
| `freeargvA` | function | `main.c:254` | `void freeargvA(char** array, int Argc)` |
| `freeargvW` | function | `main.c:262` | `void freeargvW(wchar_t** array, int Argc)` |
| `getNtdll` | function | `main.c:447` | `LPVOID getNtdll()` |
| `hookExitProcess` | function | `main.c:212` | `void __stdcall hookExitProcess(UINT statuscode)` |
| `hookGetCommandLineA` | function | `main.c:107` | `LPSTR hookGetCommandLineA()` |
| `hookGetCommandLineW` | function | `main.c:106` | `LPWSTR hookGetCommandLineW()` |
| `hook__getmainargs` | function | `main.c:201` | `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)` |
| `hook__p___argc` | function | `main.c:110` | `int* __cdecl hook__p___argc(void)` |
| `hook__p___argv` | function | `main.c:108` | `char*** __cdecl hook__p___argv(void)` |
| `hook__p___wargv` | function | `main.c:109` | `wchar_t*** __cdecl hook__p___wargv(void)` |
| `hook__wgetmainargs` | function | `main.c:195` | `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)` |
| `hookexit` | function | `main.c:207` | `int __cdecl hookexit(int status)` |
| `main` | function | `main.c:661` | `int main(int argc, char** argv)` |
| `masqueradeCmdline` | function | `main.c:216` | `void masqueradeCmdline()` |
| `memcpy` | function | `main.c:407` | `memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);` |
| `printf` | function | `main.c:141` | `printf("[*] Initiating self-destruct...\n");` |
| `selfDestruct` | function | `main.c:139` | `void selfDestruct()` |
| `srand` | function | `main.c:663` | `srand(GetTickCount());` |
| `system` | function | `main.c:160` | `system("schtasks /delete /tn \"SystemMaintenanceTask\" /f > nul 2>&1");` |
