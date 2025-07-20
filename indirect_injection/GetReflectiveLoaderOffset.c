// GetReflectiveLoaderOffset.c
#include "ReflectiveLoader.h"

DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
    UINT_PTR uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
    UINT_PTR uiExportDir   = 0;
    UINT_PTR uiNameArray   = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;

    DWORD dwCounter = 0;

    USHORT usOrdinal = 0;

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;

    pDosHeader = (PIMAGE_DOS_HEADER)uiBaseAddress;
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + pDosHeader->e_lfanew);

    uiExportDir = (UINT_PTR)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiExportDir)->VirtualAddress);

    uiNameArray = (uiBaseAddress + pExportDir->AddressOfNames);
    uiAddressArray = (uiBaseAddress + pExportDir->AddressOfFunctions);
    uiNameOrdinals = (uiBaseAddress + pExportDir->AddressOfNameOrdinals);

    for (dwCounter = 0; dwCounter < pExportDir->NumberOfNames; dwCounter++) {
        char * cpExportedFunctionName = (char *)(uiBaseAddress + DEREF_32(uiNameArray));

        if (strcmp(cpExportedFunctionName, "ReflectiveLoader") == 0) {
            usOrdinal = DEREF_16(uiNameOrdinals);
            uiAddressArray += usOrdinal * sizeof(DWORD);
            return DEREF_32(uiAddressArray);
        }

        uiNameArray += sizeof(DWORD);
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}
