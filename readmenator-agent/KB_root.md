# Subsystem: root

## aes.py
- Layer: utility
- Language: py
- Symbols:
  - `AESencrypt` (function, line 7) `def AESencrypt(plaintext, key)`
  - `dropFile` (function, line 15) `def dropFile(key, ciphertext)`

## app.py
- Layer: utility
- Doc: app.py  Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licenci
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
  - `selfDestruct` (function, line 140) `void selfDestruct()`
  - `hook__wgetmainargs` (function, line 196) `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)`
  - `hook__getmainargs` (function, line 202) `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)`
  - `hookexit` (function, line 208) `int __cdecl hookexit(int status)`
  - `hookExitProcess` (function, line 213) `void __stdcall hookExitProcess(UINT statuscode)`
  - `masqueradeCmdline` (function, line 217) `void masqueradeCmdline()`
  - `freeargvA` (function, line 255) `void freeargvA(char** array, int Argc)`
  - `freeargvW` (function, line 263) `void freeargvW(wchar_t** array, int Argc)`
  - `GetNTHeaders` (function, line 271) `char* GetNTHeaders(char* pe_buffer)`
  - `GetPEDirectory` (function, line 283) `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
  - `RepairIAT` (function, line 293) `BOOL RepairIAT(PVOID modulePtr)`
  - `_stricmp` (function, line 347) `_stricmp(func_name, "exit") == 0 ||
                    _stricmp(func_name, "_Exit") == 0 ||
    ...`
  - `RunPE` (function, line 368) `DWORD WINAPI RunPE(LPVOID lpParameter)`
  - `PELoader` (function, line 374) `void PELoader(char* data, DWORD datasize)`
  - `getNtdll` (function, line 448) `LPVOID getNtdll()`
  - `Unhook` (function, line 491) `BOOL Unhook(LPVOID cleanNtdll)`
  - `DecryptAES` (function, line 527) `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)`
  - `GetData` (function, line 560) `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)`
  - `main` (function, line 662) `int main(int argc, char** argv)`
  - `_CRT_RAND_S` (macro, line 35) `#define _CRT_RAND_S`
  - `NT_SUCCESS` (macro, line 46) `#define NT_SUCCESS(Status)`
  - `NtCurrentThread` (macro, line 49) `#define NtCurrentThread()`
  - `NtCurrentProcess` (macro, line 50) `#define NtCurrentProcess()`
  - `_CRT_SECURE_NO_WARNINGS` (macro, line 53) `#define _CRT_SECURE_NO_WARNINGS`
