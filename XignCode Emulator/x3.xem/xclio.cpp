#include "xclio.h"

DWORD dwSysEnterInstance = 0, dword_100B94B0, Destination;

// dword_100D8DCC
CRITICAL_SECTION xclio_csForCodeboxList;	// dword_100C22B4 + 0xEC
MODULE_LOADER *pLomxLoader = nullptr;
std::list<CCodeBox*> lCodeBox;				// dword_100C22B4 + 0x100
CCodeBox *pCodeBox_Probe;					// 100D8DCC

// own
BOOL InitProvider(__in xst_exports *pImports)
{
	if (!pLomxLoader)
		if (pImports->CreateProvider(LOADER_LOMX, &pLomxLoader) < 0)
			return FALSE;

	return TRUE;
}

VOID DeInitProvider()
{
	if (pLomxLoader->vfptr->baseProvider.DecInstance(pLomxLoader) == 0)
		pLomxLoader = nullptr;
}

const char * __stdcall getLicense(void *)
{
	return CInfo::getInstance().GetLicenseA();
}

uint __stdcall getData(void *, char *, uint)
{
	//printf("spoofed\n");
	return 0;
}

uint __stdcall getVersion(void *)
{
	return 40000000 + CInfo::getInstance().GetRevision();
}

int __stdcall GetXProp__Hook(void *p, uint id, void **dst)
{
	typedef struct
	{
		Padding(0x48);
		const char *(__stdcall * getLicense)(void *);	// +0x48
		Padding(0x24);
		uint(__stdcall * getData)(void *, char *, uint);	// +0x70
		Padding(0x08);
		uint(__stdcall * getVersion)(void *);	// +0x7C
	} FAKE_VF;

	static FAKE_VF fake = { { 0 }, getLicense, { 0 }, getData, { 0 }, getVersion }; // vf
	static FAKE_VF *pfake = &fake; // vfptr

	if (id == 0x71235ABE || id == 0x71235ABF) // abe
	{
		*dst = &pfake;

		return 0;
	}

	return -1; //return p->vfptr->GetXProp(p, id, dst);
}

BOOL IsInitialized()
{
	return InterlockedCompareExchange(&dwSysEnterInstance, 0, 0) != 0;
}

void Ordinal3(void(__stdcall * fnOrdinal3)(int, int, int))
{
	if (fnOrdinal3)
		fnOrdinal3(2, 0, 0);
}

// sub_10020AA4
BOOL CreateModuleLoader(PACKET_LIST *packetList)
{
	MODULE_LOADER *pLoader;
	uint signature = packetList->GetSignature();

	if (signature == IMAGE_DOS_SIGNATURE)
	{
		if (pXstImport->CreateProvider(LOADER_DOS, &pLoader) >= 0)
		{
			// free provider in the class
			packetList->Load(pLoader);

			return TRUE;
		}
	}
	else if (signature == 0x786D6F4C)	// Lomx
	{
		if (pXstImport->CreateProvider(LOADER_LOMX, &pLoader) >= 0)
		{
			// free provider in the class
			packetList->Load(pLoader);

			return TRUE;
		}
	}

	return FALSE;
}

int __cdecl sub_100210A5(wchar_t *buf)
{
	return wcsstr(buf, L"Np.12.53.") || wcsstr(buf, L"Np.3.62.?");
}

// sub_10021832
void ZCE_Scan2(XPL_WRITER **ppwWriter, PACKET_LIST *packetList)
{
	struct ZCE_CTX
	{
		uint a; // +0x00
		uint b; // +0x04
		uint c; // +0x08
		uint d; // +0x0C
		uint f; // +0x10
		uint g; // +0x14
		uint h; // +0x18
		WCHAR wszData[1024];
	};

	XPL_WRITER *writer = *ppwWriter;
	ZCE_CTX ctx;
	ZCE_ID *pAdaptersHash;

	void(__stdcall * fnImported)(void *, int, ZCE_CTX *) = (void(__stdcall *)(void *, int, ZCE_CTX *))packetList->GetImportedF();

	if (fnImported)
	{
		pAdaptersHash = CInfo::getInstance().GetAdaptersHash();
		ctx.h = 0;
		swprintf_s(ctx.wszData, L"id ...%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x:",
			pAdaptersHash->a, pAdaptersHash->b, pAdaptersHash->c, pAdaptersHash->d, pAdaptersHash->e,
			pAdaptersHash->f, pAdaptersHash->g, pAdaptersHash->h, pAdaptersHash->i, pAdaptersHash->j, pAdaptersHash->k);

		fnImported(writer->vfptr->GetRealBuffer(writer), writer->vfptr->GetRealSize(writer), &ctx);
	}
}

// sub_100590AE
uint InitPReader(XPL_READER **reader, const ubyte *request, uint req_size)
{
	int prop;
	Xdna_getData(L"{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);

	switch (prop)
	{
		case 1:	
			return pPacketProvider->vfptr->InitReader1(reader, request, req_size);
		case 2:	
			return pPacketProvider->vfptr->InitReader2(reader, request, req_size);
		default:
			return pPacketProvider->vfptr->InitReader3(reader, request, req_size);
	}
}

// sub_10059143
uint __stdcall InitPWriter(XPL_WRITER **dst, void *buf, uint size)
{
	int prop;
	Xdna_getData(L"{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);

	switch (prop)
	{
		case 1:	
			return pPacketProvider->vfptr->InitWriter1(dst, buf, size);
		default:
			return pPacketProvider->vfptr->InitWriter2(dst, buf, size);
	}
}

// sub_100214A5
XPL_WRITER ** InitWriter(XPL_WRITER **dst, void *buf, uint size)
{
	XPL_WRITER	*pWriterLocal;
	DWORD		dwErrCode;
	wchar_t		text[256];

	dwErrCode = InitPWriter(&pWriterLocal, buf, size);

	if ((dwErrCode & 0x80000000))
	{
		// dwErrCode < 0 in signed value
		pXstImport->HexToWideChar(text, 256, (const ubyte *)buf, 50, false);
		Log("PacketError %08x %ls\n", dwErrCode, text);
		SetLastError(dwErrCode);
		*dst = nullptr;
	}
	else
		*dst = pWriterLocal;

	return dst;
}

// sub_10026305
BOOL InitCleanup_sub()
{
	InterlockedExchange(&Destination, 1);
	while (InterlockedExchange(&dword_100B94B0, 0) == 1)
		Sleep(300);
	InterlockedExchange(&Destination, 0);

	EnterCriticalSection(&xclio_csForCodeboxList);

	if (pCodeBox_Probe)
	{
		lCodeBox.remove(pCodeBox_Probe);
		delete pCodeBox_Probe;
		pCodeBox_Probe = nullptr;
	}

	pCodeBox_Probe = new CCodeBox;

	if (pCodeBox_Probe)
		lCodeBox.push_back(pCodeBox_Probe);

	Log("xclio:: ZCWAVE_Init/Cleanup Reset Complete\n");

	LeaveCriticalSection(&xclio_csForCodeboxList);

	return TRUE;
}

void sub_10026E1A()
{
	pLomxLoader->vfptr->XFreeLibrary(pLomxLoader, hXpl);

	DeInitProvider();

	if (pPacketProvider)
		pPacketProvider->vfptr->baseProvider.DecInstance(pPacketProvider);

	Xdna_Clear();

	if (pXstImport->pProperties->vfptr->baseProvider.DecInstance(pXstImport->pProperties) == 0)
		pXstImport->pProperties = nullptr;

	if (hXst)
		FreeLibrary(hXst);

	hXst = NULL;
	pXstImport = nullptr;

	// sub_10026D2C(&dword_100C22B4, 0);
	{
		// v5 = *(v1 + 0xEC);
		// if (v5)
			// sub_10012EE1(v5, 1);

		CProbeEx::Destroy();

		DeleteCriticalSection(&xclio_csForCodeboxList);
	}

	// WSACleanup();
}

// sub_1002700B
BOOL SysExit_sub()
{
	if (!IsInitialized())
	{
		SetLastError(0xE0190304);

		return FALSE;
	}

	Log("xclio:: ZCWAVE_SysExit !!!\n");

	if (InterlockedDecrement(&dwSysEnterInstance) == 0)
	{
		Log("xclio:: api status check\n");

		for (int i = 0; i < 100; i++)
		{
			if (sub_10026A66())
				break;

			Sleep(10);
		}

		Log("xclio:: shutdown ready\n");

		sub_10026E1A();
	}

	return TRUE;
}

// sub_10027408
BOOL SysEnterW_sub(const wchar_t *License, const wchar_t *Path, uint Flags)
{
	int err;
	// WSADATA wsaData;
	DWORD flOldProtect;
	MEMORY_BASIC_INFORMATION mbi;

	if (InterlockedIncrement(&dwSysEnterInstance) <= 1)
	{
		// err = WSAStartup(MAKEWORD(2, 2), &wsaData);
		err = 0;
		if (err != 0)
		{
			SetLastError(err | 0xE0300000);

			return FALSE;
		}
		else
		{
			std::wstring xmag = std::wstring(Path) + L"\\xmag.xem";		// contains everything including xmina files
			std::wstring xnina = std::wstring(Path) + L"\\xnina.xem";	// contains xup.xem, xdna.xem, splash.xem, xst.xem
			std::wstring xst = std::wstring(Path) + L"\\xst.xem.dll";	// extract xst.xem somehow... lel

			// setup xst
			hXst = LoadLibraryW(xst.c_str());
			if (!hXst)
			{
				Log("xst.xem.dll\n");

				return FALSE;
			}

			xst_exports * (__stdcall * fnGetExport)() = reinterpret_cast<xst_exports * (__stdcall *)()>(GetProcAddress(hXst, (LPCSTR)1));
			if (!fnGetExport)
			{
				Log("xst@1\n");

				return FALSE;
			}

			pXstImport = fnGetExport();
			if (!pXstImport)
			{
				Log("xst@1\n");

				return FALSE;
			}

			// for NCB ZCE
			if (pXstImport->CreateProvider(PROPERTIES, &pXstImport->pProperties) < 0)
			{
				Log("pProperties\n");

				return FALSE;
			}
			VirtualQuery(&pXstImport->pProperties->vfptr->GetXProp, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &flOldProtect);
			pXstImport->pProperties->vfptr->GetXProp = GetXProp__Hook;
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect);

			if (!InitProvider(pXstImport))
			{
				Log("SysEnterW InitProvider\n");

				return FALSE;
			}

			// maybe a bad idea...
#ifdef xc_update
			HMODULE hXup;
			MODULE_CTX xdna_ctx, splash_ctx;
			typedef int(__stdcall * rva_1T)(const wchar_t *Path, void *xdna, uint xdna_size);
			typedef int(__stdcall * rva_12T)(const wchar_t *Path, void *xdna, uint xdna_size, void *splash, uint splash_size);

			if (!XmagLoadLibrary(pLomxLoader, xnina.c_str(), "xup.xem", &hXup))
			{
				Log("SysEnterW XmagLoadLibrary\n");
				return FALSE;
			}

			if (GetXmagFileInfo(xnina.c_str(), "xdna.xem", &xdna_ctx))
			{
				if (GetXmagFileInfo(xnina.c_str(), "splash.xem", &splash_ctx))
				{
					rva_1T update =
						(rva_1T)pLomxLoader->vfptr->XGetProcAddress(pLomxLoader, hXup, (LPCSTR)1); // only image
					if (update)
					{
						if (update(Path, xdna_ctx.packedBuf, xdna_ctx.size) < 0)
						{
							Log("update failed\n");
							// return FALSE;
						}
					}
					free(splash_ctx.packedBuf);
				}
				free(xdna_ctx.packedBuf);
			}
			pLomxLoader->vfptr->XFreeLibrary(pLomxLoader, hXup);
#endif
			// xpl.xem
			if (!LomxLoadLibrary(pLomxLoader, xmag.c_str(), "xpl.xem", &hXpl))
			{
				Log("SysEnterW xpl.xem\n");

				return FALSE;
			}
			CreatePacketProviderT fnCreatePacketProvider = (CreatePacketProviderT)pLomxLoader->vfptr->XGetProcAddress(pLomxLoader, hXpl, "CreatePacketProvider");
			if (!fnCreatePacketProvider)
			{
				Log("SysEnterW fnCreatePacketProvider\n");

				return FALSE;
			}

			pPacketProvider = fnCreatePacketProvider();
			if (!pPacketProvider)
			{
				Log("SysEnterW CreatePacketProvider\n");

				return FALSE;
			}

			if (!Xdna_Init(xnina.c_str()))
			{
				Log("Xdna_Init\n");

				return FALSE;
			}

			if (!CInfo::getInstance().GrabInfo(xnina.c_str()))
			{
				Log("GrabInformation\n");

				return FALSE;
			}

			// sub_10019055
			// CProbeEx::getInstance(); // new

			InitializeCriticalSection(&xclio_csForCodeboxList);

			Log("xclio:: WOW, XIGNCODE SYSTEM %d INITIALIZATION IS COMPLETE !!!\n", CInfo::getInstance().GetRevision());
		}
	}

	return TRUE;
}

// sub_10028F82
BOOL XIGNAPI Xclio_SysEnterA(const char *License, const char *Path, uint Flags)
{
	WCHAR wszBufLicense[MAX_PATH];
	WCHAR wszBufPath[MAX_PATH];
	WCHAR *pwszLicense = NULL;
	WCHAR *pwszPath = NULL;

	if (License)
	{
		MultiByteToWideChar(CP_ACP, 0, License, -1, wszBufLicense, MAX_PATH);
		pwszLicense = wszBufLicense;
	}

	if (Path)
	{
		MultiByteToWideChar(CP_ACP, 0, Path, -1, wszBufPath, MAX_PATH);
		pwszPath = wszBufPath;
	}

	return Xclio_SysEnterW(pwszLicense, pwszPath, Flags);
}

BOOL XIGNAPI Xclio_SysEnterW(const wchar_t *License, const wchar_t *Path, uint Flags)
{
	if (!SysEnterW_sub(License, Path, Flags))
		return FALSE;

	return Xclio_Init();
}

BOOL XIGNAPI Xclio_SysExit()
{
	Xclio_Cleanup();

	return SysExit_sub();
}

// sub_100264AB
BOOL XIGNAPI Xclio_Init()
{
	CXLock xlock;
	xlock.Empty();

	if (!IsInitialized())
	{
		SetLastError(0xE0190304);

		return FALSE;
	}

	return InitCleanup_sub();
}

// g
BOOL XIGNAPI Xclio_Cleanup()
{
	CXLock xlock;
	xlock.Empty();

	if (!IsInitialized())
	{
		SetLastError(0xE0190304);

		return FALSE;
	}

	return InitCleanup_sub();
}

// 100250D8
BOOL XIGNAPI Xclio_Probe(const unsigned char *request, unsigned char *response, uint req_size)
{
	CXLock xlock;
	XPL_READER *reader;
	wchar_t text[256];
	int prop;
	BOOL result = FALSE;

	xlock.Empty();

	if (!IsInitialized())
	{
		// sysenter pls
		SetLastError(0xE0190304);

		return FALSE;
	}

	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
		return TRUE;

	EnterCriticalSection(&xclio_csForCodeboxList);

	if (!pCodeBox_Probe)
	{
		SetLastError(0xE0190304);
		LeaveCriticalSection(&xclio_csForCodeboxList);

		return FALSE;
	}

	// init xpl reader
	int error = InitPReader(&reader, request, req_size);
	if (error < 0)
	{
		// fail to init reader
		Xdna_getData(L"{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);
		pXstImport->HexToWideChar(text, 256, request, 50, false);
		Log("xclio:: SC Packet Parsing Error S=>%08x P=>%d SZ=>%d H=>%s\n", error, prop, req_size, text);
		SetLastError(error);
	}
	else
	{
		error = pCodeBox_Probe->HandlePacket(reader, response, req_size);
		reader->vfptr->DecInstance(reader);
		if (error == 2)
		{
			SetLastError(0xE0190302);
		}
		else if (error != 0)
		{
			SetLastError(0xE0190305);
		}
		else
		{
			// no error
			result = TRUE;
		}
	}
	LeaveCriticalSection(&xclio_csForCodeboxList);

	return result;
}

BOOL XIGNAPI Xclio_ProbeEx(const unsigned char *request, uint req_size, ProbeCallbackT callback, void *context)
{
	CXLock xlock;
	xlock.Empty();

	if (!IsInitialized())
	{
		Log("Xclio_ProbeEx SysEnter PLEASE!\n");
		SetLastError(0xE0190304);

		return FALSE;
	}

	// sub_10024ADE();
	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
		return TRUE;

	// dword_100D8DCC codebox
	int error = CProbeEx::GetInstance()->AddContext(pCodeBox_Probe, request, req_size, req_size, callback, context);
	if (error < 0)
	{
		SetLastError(error);

		return FALSE;
	}

	return TRUE;
}

void * XIGNAPI Xclio_CreateCodeBox()
{
	CCodeBox *pCodeBox;
	CXLock xlock;

	xlock.Empty();

	if (IsInitialized())
	{
		EnterCriticalSection(&xclio_csForCodeboxList);
		pCodeBox = new CCodeBox;

		if (pCodeBox)
		{
			lCodeBox.push_back(pCodeBox);
			LeaveCriticalSection(&xclio_csForCodeboxList);

			return pCodeBox;
		}

		LeaveCriticalSection(&xclio_csForCodeboxList);
	}
	else
		SetLastError(0xE0190304);

	return nullptr;
}

BOOL XIGNAPI Xclio_CloseCodeBox(void *CodeBox)
{
	BOOL result;

	CXLock xlock;
	xlock.Empty();

	if (IsInitialized())
	{
		EnterCriticalSection(&xclio_csForCodeboxList);
		lCodeBox.remove((CCodeBox *)CodeBox);
		LeaveCriticalSection(&xclio_csForCodeboxList);
		result = TRUE;
	}
	else
	{
		SetLastError(0xE0190304);
		result = FALSE;
	}

	return result;
}

BOOL XIGNAPI Xclio_ProbeCodeBox(void *CodeBox, const unsigned char *request, void *response, uint size)
{
	XPL_READER	*reader;
	WCHAR		szHex[256];
	CXLock		xlock;
	int prop;

	xlock.Empty();

	if (!IsInitialized())
	{
		SetLastError(0xE0190304);

		return FALSE;
	}

	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
	{
		Log("xclio:: ResetPending Skip\n");

		return FALSE;
	}

	auto it = std::find(lCodeBox.begin(), lCodeBox.end(), CodeBox);
	if (it == lCodeBox.end())
	{
		SetLastError(0xE0190301);

		return FALSE;
	}

	if (strcmp((const char *)request, "ECHOTEST") == 0)
	{
		Log("xclio:: ProbeECHO Complete - 1 %d\n", size);
		memcpy(response, request, size);

		return TRUE;
	}

	// init xpl reader
	int error = InitPReader(&reader, request, size);
	if (error < 0)
	{
		Xdna_getData(L"{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);
		pXstImport->HexToWideChar(szHex, 256, request, 50, false);
		Log("xclio:: SC Packet Parsing Error S=>%08x P=>%d SZ=>%d H=>%s\n", error, prop, size, szHex);
		SetLastError(error);

		return FALSE;
	}

	error = reinterpret_cast<CCodeBox *>(CodeBox)->HandlePacket(reader, response, size);
	reader->vfptr->DecInstance(reader);

	if (error == 2)
	{
		SetLastError(0xE0190302);
	}
	else if (error != 0)
	{
		SetLastError(0xE0190305);
	}
	else
	{
		// no error
		return TRUE;
	}

	return FALSE;
}

BOOL XIGNAPI Xclio_ProbeCodeBoxEx(void *CodeBox, const unsigned char *request, uint req_size, uint res_size, ProbeCallbackT Callback, void *Context)
{
	int error;
	CXLock xlock;
	xlock.Empty();

	if (!IsInitialized())
	{
		SetLastError(0xE0190304);

		return FALSE;
	}

	InterlockedExchange(&dword_100B94B0, 1);
	if (InterlockedCompareExchange(&Destination, 1, 1) == 1)
		return TRUE;

	auto it = std::find(lCodeBox.begin(), lCodeBox.end(), CodeBox);
	if (it == lCodeBox.end())
	{
		SetLastError(0xE0190301);

		return FALSE;
	}

	error = CProbeEx::GetInstance()->AddContext(CodeBox, request, req_size, res_size, Callback, Context);
	if (error < 0)
	{
		SetLastError(error);

		return FALSE;
	}

	return TRUE;
}

VOID XIGNAPI Xclio_RegisterCallback(XigncodeCallbackT Callback, void *Context)
{
	CInfo::getInstance().SetCallbackInfo(Callback, Context);
}

// sub_10022B22
BOOL QueryFastFunction(uint fid, void **dst)
{
	switch (fid)
	{
		case 0x7D0:
			*dst = LoadLibraryA;
			break;
		case 0x834:
			*dst = LoadLibraryW;
			break;
		case 0x960:
			*dst = FreeLibrary;
			break;
		case 0x9C4:
			*dst = GetProcAddress;
			break;
		case 0xC80:
			*dst = free;
			break;
		case 0xC1C:
			*dst = malloc;
			break;
		case 0xCE4:
			*dst = fopen_s;
			break;
		case 0xD48:
			*dst = fclose;
			break;
		case 0xDAC:
			*dst = fread;
			break;
		case 0xE10:
			*dst = fwrite;
			break;
		case 0xE74:
			*dst = fseek;
			break;
		case 0xED8:
			*dst = ftell;
			break;
		case 0xEE2:
			*dst = CreateFileA;
			break;
		case 0xEEC:
			*dst = CreateFileW;
			break;
		case 0xEF6:
			*dst = ReadFile;
			break;
		case 0xF00:
			*dst = WriteFile;
			break;
		case 0xF0A:
			*dst = SetFilePointer;
			break;
		case 0xF14:
			*dst = vfscanf;
			break;
		case 0xF1E:
			*dst = vfwscanf;
			break;
		case 0xF28:
			*dst = fopen_s;
			break;
		case 0xF32:
			*dst = _wfopen_s;
			break;
		case 0xF3C:
			*dst = vfprintf;
			break;
		case 0xF46:
			*dst = vfwprintf;
			break;
		default:
			SetLastError(0xE0010002);
			return FALSE;
	}
	return TRUE;
}

BOOL XIGNAPI Xclio_SendCommandVa(uint cid, va_list ap)
{
	CXLock xlock;
	xlock.Empty();

	if (!IsInitialized())
	{
		SetLastError(0xE0190304);

		return FALSE;
	}

	switch (cid)
	{
		case 0x64:
		{
			// MyUserInfoCallback(unsigned int iid, char *buffer, unsigned int size, void *context)
			uint callback = va_arg(ap, uint);
			uint context = va_arg(ap, uint);
			Log("xclio:: set user info callback A %08X, %08X\n", callback, context);
			break;
		}
		case 0x1BBC:
		{
			uint fid = va_arg(ap, uint);
			void **dst = va_arg(ap, void **);

			return QueryFastFunction(fid, dst);
		}
		default:
		{
			Log("SendCommandVa cid = %08X\n", cid);
			SetLastError(0xE0010002);

			return FALSE;
		}
	}

	return TRUE;
}