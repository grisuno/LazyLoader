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
- Defined: `main.c:140`

### hook__wgetmainargs (function) `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)`
- Defined: `main.c:196`

### hook__getmainargs (function) `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)`
- Defined: `main.c:202`

### hookexit (function) `int __cdecl hookexit(int status)`
- Defined: `main.c:208`

### hookExitProcess (function) `void __stdcall hookExitProcess(UINT statuscode)`
- Defined: `main.c:213`

### masqueradeCmdline (function) `void masqueradeCmdline()`
- Defined: `main.c:217`

### freeargvA (function) `void freeargvA(char** array, int Argc)`
- Defined: `main.c:255`

### freeargvW (function) `void freeargvW(wchar_t** array, int Argc)`
- Defined: `main.c:263`

### GetNTHeaders (function) `char* GetNTHeaders(char* pe_buffer)`
- Defined: `main.c:271`

### GetPEDirectory (function) `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
- Defined: `main.c:283`

### RepairIAT (function) `BOOL RepairIAT(PVOID modulePtr)`
- Defined: `main.c:293`

### _stricmp (function) `_stricmp(func_name, "exit") == 0 ||
                    _stricmp(func_name, "_Exit") == 0 ||
    ...`
- Defined: `main.c:347`

### RunPE (function) `DWORD WINAPI RunPE(LPVOID lpParameter)`
- Defined: `main.c:368`

### PELoader (function) `void PELoader(char* data, DWORD datasize)`
- Defined: `main.c:374`

### getNtdll (function) `LPVOID getNtdll()`
- Defined: `main.c:448`

### Unhook (function) `BOOL Unhook(LPVOID cleanNtdll)`
- Defined: `main.c:491`

### DecryptAES (function) `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)`
- Defined: `main.c:527`

### GetData (function) `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)`
- Defined: `main.c:560`

### main (function) `int main(int argc, char** argv)`
- Defined: `main.c:662`
