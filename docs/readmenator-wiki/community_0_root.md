# root

*Community 0 | 4 files | cohesion 1.00*

## Definition

This community groups 4 file(s) rooted at `root` with dominant language py (cohesion 1.00). Central symbols: `12`, `AESencrypt`, `DATA`, `DecryptAES`, `GetData`, `GetNTHeaders`, `GetPEDirectory`, `NTSTATUS`. Core file: `main.c` (34 symbols). Documented purpose: Autor: Gris Iscomeback Correo electrónico: grisiscomeback[at]gmail[dot]com Fecha de creación: xx/xx/xxxx Licencia: GPL v3  Descripción:.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `aes.py` | py | utility | 2 | no |
| `app.py` | py | utility | 0 | yes |
| `install.sh` | sh | utility | 0 | no |
| `main.c` | c | utility | 34 | no |

## Key Symbols

- `AESencrypt` (function, `aes.py:7`) `def AESencrypt(plaintext, key)`
- `dropFile` (function, `aes.py:15`) `def dropFile(key, ciphertext)`
- `_CRT_RAND_S` (macro, `main.c:35`) `#define _CRT_RAND_S`
- `NT_SUCCESS` (macro, `main.c:46`) `#define NT_SUCCESS(Status)`
- `NtCurrentThread` (macro, `main.c:49`) `#define NtCurrentThread()`
- `NtCurrentProcess` (macro, `main.c:50`) `#define NtCurrentProcess()`
- `_CRT_SECURE_NO_WARNINGS` (macro, `main.c:53`) `#define _CRT_SECURE_NO_WARNINGS`
- `NTSTATUS` (type_alias, `main.c:54`) `typedef LONG NTSTATUS;` - pragma warning(disable: 4996) define _CRT_SECURE_NO_WARNINGS
- `12` (type_alias, `main.c:56`) `typedef struct _BASE_RELOCATION_ENTRY { WORD Offset : 12;`
- `_BASE_RELOCATION_ENTRY` (struct, `main.c:57`)
- `DATA` (struct, `main.c:62`)
- `hookGetCommandLineW` (function, `main.c:106`) `LPWSTR hookGetCommandLineW()` - Implementación de hooks
- `hookGetCommandLineA` (function, `main.c:107`) `LPSTR hookGetCommandLineA()`
- `hook__p___argv` (function, `main.c:108`) `char*** __cdecl hook__p___argv(void)`
- `hook__p___wargv` (function, `main.c:109`) `wchar_t*** __cdecl hook__p___wargv(void)`
- `hook__p___argc` (function, `main.c:110`) `int* __cdecl hook__p___argc(void)`
- `anti_analysis` (function, `main.c:115`) `BOOL anti_analysis()` - === ANTI-ANALYSIS ===
- `selfDestruct` (function, `main.c:140`) `void selfDestruct()`
- `hook__wgetmainargs` (function, `main.c:196`) `int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _usele`
- `hook__getmainargs` (function, `main.c:202`) `int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, vo`
- `hookexit` (function, `main.c:208`) `int __cdecl hookexit(int status)`
- `hookExitProcess` (function, `main.c:213`) `void __stdcall hookExitProcess(UINT statuscode)`
- `masqueradeCmdline` (function, `main.c:217`) `void masqueradeCmdline()`
- `freeargvA` (function, `main.c:255`) `void freeargvA(char** array, int Argc)`
- `freeargvW` (function, `main.c:263`) `void freeargvW(wchar_t** array, int Argc)`
- `GetNTHeaders` (function, `main.c:271`) `char* GetNTHeaders(char* pe_buffer)`
- `GetPEDirectory` (function, `main.c:283`) `IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)`
- `RepairIAT` (function, `main.c:293`) `BOOL RepairIAT(PVOID modulePtr)`
- `_stricmp` (function, `main.c:347`) `_stricmp(func_name, "exit") == 0 \|\|                     _stricmp(func_name, "_Ex`
- `RunPE` (function, `main.c:368`) `DWORD WINAPI RunPE(LPVOID lpParameter)`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- [dataflow UNCHECKED_ALLOC] `aes.py:25` `dropFile` `file`: Result of allocator stored in `file` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `main.c:681` `main` `whost`: Result of allocator stored in `whost` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `main.c:685` `main` `wpe`: Result of allocator stored in `wpe` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `main.c:689` `main` `wkey`: Result of allocator stored in `wkey` is never checked against NULL.

## Open Questions

- Why do 3 file(s) lack file-level docs (e.g. `aes.py`)? What purpose do they serve?
- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `aes.py`
- `app.py`
- `install.sh`
- `main.c`
