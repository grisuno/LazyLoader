# API

## aes.py

### AESencrypt `def AESencrypt(plaintext, key)`
- Defined: `aes.py:7`

### dropFile `def dropFile(key, ciphertext)`
- Defined: `aes.py:15`

## main.c

### hookGetCommandLineW `LPWSTR hookGetCommandLineW()`
- Defined: `main.c:106`
- Doc: Implementación de hooks

### hookGetCommandLineA `LPSTR hookGetCommandLineA()`
- Defined: `main.c:107`

### hook__p___argv `char*** __cdecl hook__p___argv(void)`
- Defined: `main.c:108`

### hook__p___wargv `wchar_t*** __cdecl hook__p___wargv(void)`
- Defined: `main.c:109`

### hook__p___argc `int* __cdecl hook__p___argc(void)`
- Defined: `main.c:110`

### anti_analysis `BOOL anti_analysis()`
- Defined: `main.c:115`
- Doc: === ANTI-ANALYSIS ===

### selfDestruct `void selfDestruct()`
- Defined: `main.c:139`

### hook__wgetmainargs `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)`
- Defined: `main.c:195`

### hook__getmainargs `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)`
- Defined: `main.c:201`

### hookexit `int __cdecl hookexit(int status)`
- Defined: `main.c:207`

### hookExitProcess `void __stdcall hookExitProcess(UINT statuscode)`
- Defined: `main.c:212`

### masqueradeCmdline `void masqueradeCmdline()`
- Defined: `main.c:216`

### freeargvA `void freeargvA(char** array, int Argc)`
- Defined: `main.c:254`

### freeargvW `void freeargvW(wchar_t** array, int Argc)`
- Defined: `main.c:262`

### GetNTHeaders `char* GetNTHeaders(char* pe_buffer)`
- Defined: `main.c:270`

### GetPEDirectory `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
- Defined: `main.c:282`

### RepairIAT `BOOL RepairIAT(PVOID modulePtr)`
- Defined: `main.c:292`

### _stricmp `_stricmp(func_name, "exit") == 0 ||
                    _stricmp(func_name, "_Exit") == 0 ||
    ...`
- Defined: `main.c:347`

### RunPE `DWORD WINAPI RunPE(LPVOID lpParameter)`
- Defined: `main.c:367`

### PELoader `void PELoader(char* data, DWORD datasize)`
- Defined: `main.c:373`

### getNtdll `LPVOID getNtdll()`
- Defined: `main.c:447`

### Unhook `BOOL Unhook(LPVOID cleanNtdll)`
- Defined: `main.c:490`

### DecryptAES `void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen)`
- Defined: `main.c:526`

### GetData `DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource)`
- Defined: `main.c:559`

### main `int main(int argc, char** argv)`
- Defined: `main.c:661`
