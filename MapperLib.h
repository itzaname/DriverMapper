#pragma once


#pragma comment(lib, "DriverMapper.lib")

extern UINT MapDriver(HANDLE hVBox, LPWSTR lpDriverFullName);
extern UINT MapDriverBuffer(HANDLE hVBox, PVOID image);
extern DWORD TestImports(PVOID pImageBase);