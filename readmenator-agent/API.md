# API

## aes.py
- `AESencrypt` (function) `aes.py:7` `def AESencrypt(plaintext, key)`
- `dropFile` (function) `aes.py:15` `def dropFile(key, ciphertext)`

## main.c
- `hookGetCommandLineW` (function) `main.c:106` `LPWSTR hookGetCommandLineW()` -- Implementación de hooks
- `hookGetCommandLineA` (function) `main.c:107` `LPSTR hookGetCommandLineA()`
- `hook__p___argv` (function) `main.c:108` `char*** __cdecl hook__p___argv(void)`
- `hook__p___wargv` (function) `main.c:109` `wchar_t*** __cdecl hook__p___wargv(void)`
- `hook__p___argc` (function) `main.c:110` `int* __cdecl hook__p___argc(void)`
- `anti_analysis` (function) `main.c:115` `BOOL anti_analysis()` -- === ANTI-ANALYSIS ===
- `selfDestruct` (function) `main.c:140` `void selfDestruct()`
- `hook__wgetmainargs` (function) `main.c:196` `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)`
- `hook__getmainargs` (function) `main.c:202` `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)`
- `hookexit` (function) `main.c:208` `int __cdecl hookexit(int status)`
- `hookExitProcess` (function) `main.c:213` `void __stdcall hookExitProcess(UINT statuscode)`
- `masqueradeCmdline` (function) `main.c:217` `void masqueradeCmdline()`
- `freeargvA` (function) `main.c:255` `void freeargvA(char** array, int Argc)`
- `freeargvW` (function) `main.c:263` `void freeargvW(wchar_t** array, int Argc)`
- `GetNTHeaders` (function) `main.c:271` `char* GetNTHeaders(char* pe_buffer)`
- `GetPEDirectory` (function) `main.c:283` `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
- `RepairIAT` (function) `main.c:293` `BOOL RepairIAT(PVOID modulePtr)`
- `RunPE` (function) `main.c:368` `DWORD WINAPI RunPE(LPVOID lpParameter)`
- `PELoader` (function) `main.c:374` `void PELoader(char* data, DWORD datasize)`
- `getNtdll` (function) `main.c:448` `LPVOID getNtdll()`
- `Unhook` (function) `main.c:491` `BOOL Unhook(LPVOID cleanNtdll)`
- `DecryptAES` (function) `main.c:527` `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)`
- `GetData` (function) `main.c:560` `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)`
- `main` (function) `main.c:662` `int main(int argc, char** argv)`
