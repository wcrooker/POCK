#pragma once
#include <windows.h>

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

HMODULE ReflectiveLoad(const BYTE *rawImage, SIZE_T imageSize);
