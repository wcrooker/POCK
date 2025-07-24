#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include "reflective_loader.h"

#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))

HMODULE ReflectiveLoad(const BYTE *rawImage, SIZE_T imageSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)rawImage;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(rawImage + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    SIZE_T imageSizeAligned = nt->OptionalHeader.SizeOfImage;
    LPVOID baseAddress = VirtualAlloc(NULL, imageSizeAligned, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!baseAddress) return NULL;

    // Copy headers
    memcpy(baseAddress, rawImage, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPBYTE)baseAddress + section[i].VirtualAddress;
        LPVOID src  = (LPBYTE)rawImage + section[i].PointerToRawData;
        memcpy(dest, src, section[i].SizeOfRawData);
    }

    // Relocations
    SIZE_T delta = (SIZE_T)baseAddress - nt->OptionalHeader.ImageBase;
    if (delta) {
        if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)baseAddress +
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

            DWORD size = 0;
            while (reloc->VirtualAddress && reloc->SizeOfBlock) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *relInfo = (WORD *)(reloc + 1);

                for (DWORD i = 0; i < count; i++) {
                    DWORD type = relInfo[i] >> 12;
                    DWORD offset = relInfo[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD *patch = (DWORD *)((LPBYTE)baseAddress + reloc->VirtualAddress + offset);
                        *patch += (DWORD)delta;
                    } else if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG *patch = (ULONGLONG *)((LPBYTE)baseAddress + reloc->VirtualAddress + offset);
                        *patch += delta;
                    }
                }

                reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // Import resolution
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)baseAddress +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDesc->Name) {
            char *dllName = (char *)((LPBYTE)baseAddress + importDesc->Name);
            HMODULE hDLL = LoadLibraryA(dllName);
            if (!hDLL) return NULL;

            PIMAGE_THUNK_DATA origFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)baseAddress + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)baseAddress + importDesc->FirstThunk);

            while (origFirstThunk->u1.AddressOfData) {
                FARPROC func = NULL;
                if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    func = GetProcAddress(hDLL, (LPCSTR)(origFirstThunk->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)baseAddress + origFirstThunk->u1.AddressOfData);
                    func = GetProcAddress(hDLL, import->Name);
                }

                if (!func) return NULL;
                firstThunk->u1.Function = (ULONGLONG)func;
                origFirstThunk++;
                firstThunk++;
            }

            importDesc++;
        }
    }

    // Optional: call entry point manually
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        DllMain_t DllEntry = (DllMain_t)((LPBYTE)baseAddress + nt->OptionalHeader.AddressOfEntryPoint);
        BOOL success = DllEntry((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, NULL);
        if (!success) {
            VirtualFree(baseAddress, 0, MEM_RELEASE);
            return NULL;
        }
    }

    return (HMODULE)baseAddress;
}
