#pragma once
#include <windows.h>
#include <winternl.h>

#define IOCTL_GLCKIO_MAPPHYSTOLIN 0x80102040
#define IOCTL_GLCKIO_UNMAPPHYSADDR 0x80102044

#pragma pack (push,1)
// Our structures that we pass to the driver (IN) values are required and (OUT) values are the one returned back to us
typedef struct _SECTION_MAP
{
	IN SIZE_T CommitSize;
	IN PLARGE_INTEGER SectionOffset;
	OUT HANDLE SectionHandle;
	OUT PVOID BaseAddress; // Usermode memory address
	OUT PVOID Object; // Kernelmode object address
} SECTION_MAP;
#pragma pack(pop)

typedef struct _POOL_HEADER
{
	ULONG ulong1;
	ULONG PoolTag;
} POOL_HEADER, *PPOOL_HEADER;

typedef struct _EX_FAST_REF
{
	union {
		PVOID Object;
		ULONG_PTR RefCnt : 3;
		ULONG_PTR Value;
	};
} EX_FAST_REF, *PEX_FAST_REF;