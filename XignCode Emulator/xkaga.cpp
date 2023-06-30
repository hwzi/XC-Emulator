#include "stdafx.h"

#include "utils.h"
#include "xkaga.h"
#include "xigncode.h"

HMODULE xkaga_xem = NULL;
DWORD xkaga_size;

void __stdcall empty_spoof(void *arg0, void *arg1)
{
}

void __stdcall scan_check_spoof(void *arg0, void *arg1)
{
	LPXC_CLASS lp = (LPXC_CLASS)arg1;
	lp->vfptr->updated(lp, arg0, 3000);
}

void __stdcall window_check_spoof(void *arg0, void *arg1)
{
	LPXC_CLASS lp = (LPXC_CLASS)arg1;
	lp->vfptr->updated(lp, arg0, 2000);
}

void __stdcall multiple_check_spoof(void *arg0, void *arg1)
{
	typedef struct _XKAGA
	{
		unsigned char padding1[0x28];
		struct
		{
			unsigned char padding1[0x20];
			struct
			{
				struct
				{
					unsigned char padding1[0x11C];
					void(__stdcall * _do)(void*, wchar_t*, void*);
				} *vfptr;
			} *p;
		} *p;
	} XKAGA, *PXKAGA, *LPXKAGA;

	LPXC_CLASS lp = (LPXC_CLASS)arg1;

	if (lp->vfptr->wait(lp, 0))
		return;

	LPXKAGA lpXKaga = (LPXKAGA)arg0;
	lpXKaga->p->p->vfptr->_do(lpXKaga->p->p, L"{83789C4B-DB87-4ad9-8E9A-96FC0C70F068}", xkaga_xem);

	if (lp->vfptr->wait(lp, 0))
		return;

	lp->vfptr->updated(lp, arg0, 30000);
}

void __stdcall prefetch_check_spoof(void *arg0, void *arg1)
{
	LPXC_CLASS lp = (LPXC_CLASS)arg1;
	lp->vfptr->updated(lp, arg0, 60000);
}

/*void __stdcall collect_items_spoof(void *arg0)
{
	 LPXC_CLASS lp = (LPXC_CLASS)arg0;
	 lp->vfptr->updated(lp, arg0, 60000);
}*/

void xkaga_operation(void **lplpDetectFunction)
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
	dwDistance = (DWORD)lpDetectFunction - (DWORD)xkaga_xem;

	// 0x000065F5 scan
	// 0x000081EB window check
	// 0x00009E50 prefetch
	// 0x0000A390 init?
	// 0x0000B0DA multiple checks (module process driver)
	// 0x0000EAC0 ?
	// 0x0000FAC8 vms
	// 0x00012198 ?

	if (dwDistance == 0x000065F5)
	{
		printf("\t\tscan check function patched %08X\n", lpDetectFunction);

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = scan_check_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
	else if(dwDistance == 0x000081EB)
	{
		printf("\t\twindow check function patched %08X\n", lpDetectFunction);

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = window_check_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
	else if (dwDistance == 0x00009E50)
	{
		printf("\t\tprefetch check function patched %08X\n", lpDetectFunction);

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = prefetch_check_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
	else if (dwDistance == 0x0000B0DA)
	{
		printf("\t\tmultiple check function patched %08X\n", lpDetectFunction);

		/*
		LPVOID lpvLolz = (PBYTE)xkaga_xem + 0x3DCA;
		VirtualQuery(lpvLolz, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		DetourFunction(TRUE, &lpvLolz, collect_items_spoof);
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
		*/

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = multiple_check_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
	else
	{
		printf("\t\txkaga %08X - %08X\n", lpDetectFunction, dwDistance);

		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
		*lplpDetectFunction = empty_spoof;
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);
	}
}