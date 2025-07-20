#pragma once

#include <windows.h>

// ----------------------------------------
// Macro helpers used by ReflectiveLoader.c
// ----------------------------------------
#define DEREF(name)              *(ULONG_PTR *)(name)
#define DEREF_32(name)           *(DWORD *)(name)
#define DEREF_16(name)           *(WORD *)(name)
#define DLLEXPORT                __attribute__((dllexport))
#define DLL_QUERY_HMODULE        6
#define _ReturnAddress()         (__builtin_return_address(0))
#define __readgsqword(x)         __builtin_ia32_rdgsbase64() // Fake definition just to silence errors on mingw-w64

// ----------------------------------------
// Image reloc type fallback
// ----------------------------------------
#define IMAGE_REL_BASED_DIR64    10
#define IMAGE_REL_BASED_HIGHLOW  3
#define IMAGE_REL_BASED_HIGH     1
#define IMAGE_REL_BASED_LOW      2

typedef struct {
  WORD offset : 12;
  WORD type   : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

// ----------------------------------------
// Typedefs for WinAPI function pointers
// ----------------------------------------
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *NTFLUSHINSTRUCTIONCACHE)(HANDLE, LPCVOID, SIZE_T);

// ----------------------------------------
// Hash constants used for API resolving
// (Values must match original source hashes!)
// ----------------------------------------
#define KERNEL32DLL_HASH  0x6A4ABC5B
#define NTDLLDLL_HASH     0x3CFA685D
#define LOADLIBRARYA_HASH 0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA
#define VIRTUALALLOC_HASH 0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

// ----------------------------------------
// Rotate right function used for hashing
// ----------------------------------------
__forceinline DWORD ror(DWORD d) {
  return (d >> 13) | (d << (32 - 13));
}

// ----------------------------------------
// Simple hash function for API resolving
// ----------------------------------------
__forceinline DWORD hash(const char *c) {
  register DWORD h = 0;
  while (*c) {
    h = ror(h);
    h += *c >= 'a' ? *c - 0x20 : *c;
    c++;
  }
  return h;
}

DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer );