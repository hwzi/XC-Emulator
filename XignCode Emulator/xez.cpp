#include "stdafx.h"

#include "xez.h"
#include "xigncode.h"

HMODULE xez_xem = NULL;
DWORD xez_size;

void __stdcall xez_window_check_spoof(void *arg0, void *arg1)
{
	LPXC_CLASS lp = (LPXC_CLASS)arg1;
	lp->vfptr->updated(lp, arg0, 1000);
}


void __stdcall api_check_spoof(void *arg0, void *arg1)
{
	LPXC_CLASS lp = (LPXC_CLASS)arg1;
	lp->vfptr->updated(lp, arg0, 5000);
}

void xez_operation(void **lplpDetectFunction)
{
	DWORD dwDistance;
	DWORD flOldProtect;
	LPVOID lpDetectFunction;
	MEMORY_BASIC_INFORMATION mbi;

	if (VirtualQuery(lplpDetectFunction, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
	{
		printf("VirtualQuery failed %08X\n", GetLastError());

		return;
	}

	lpDetectFunction = *lplpDetectFunction;
	dwDistance = (DWORD)lpDetectFunction - (DWORD)xez_xem;

	// 0x000103F2 window check
	// 0x0002C67E api check aob:
	// 55 8B EC 83 EC ? ? 8B ? 0C ? 8B ? 08 83 ? ? 00 89 ? ? 75
	if (dwDistance == 0x000103F2)
	{
		printf("\t\twindow check function patched %08X\n", lpDetectFunction);

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = xez_window_check_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
	else if (dwDistance == 0x0002C67E)
	{
		printf("\t\tapi check function patched %08X\n", lpDetectFunction);

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = api_check_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
}