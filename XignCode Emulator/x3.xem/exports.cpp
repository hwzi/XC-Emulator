#include "global.h"

#include "xclio.h"
#include "log.h"

BOOL XIGNAPI SysEnterA(const char *License, const char *Path, unsigned int Flags)
{
	return Xclio_SysEnterA(License, Path, Flags);
}

BOOL XIGNAPI SysEnterW(const wchar_t *License, const wchar_t *Path, unsigned int Flags)
{
	return Xclio_SysEnterW(License, Path, Flags);
}

BOOL XIGNAPI SysExit()
{
	return Xclio_SysExit();
}

BOOL XIGNAPI Init()
{
	return Xclio_Init();
}

BOOL XIGNAPI Cleanup()
{
	return Xclio_Cleanup();
}

BOOL XIGNAPI Probe(const unsigned char *request, unsigned char *response, unsigned int req_size)
{
	return Xclio_Probe(request, response, req_size);
}

BOOL XIGNAPI ProbeEx(const unsigned char *request, unsigned int req_size, ProbeCallbackT callback, void *context)
{
	return Xclio_ProbeEx(request, req_size, callback, context);
}

void * XIGNAPI CreateCodeBox()
{
	return Xclio_CreateCodeBox();
}

BOOL XIGNAPI CloseCodeBox(void *CodeBox)
{
	return Xclio_CloseCodeBox(CodeBox);
}

BOOL XIGNAPI ProbeCodeBox(void *codebox, const unsigned char *request, void *response, unsigned int res_size)
{
	return Xclio_ProbeCodeBox(codebox, request, response, res_size);
}

BOOL XIGNAPI ProbeCodeBoxEx(void *codebox, const unsigned char *request, unsigned int req_size, unsigned int res_size, ProbeCallbackT callback, void *context)
{
	return Xclio_ProbeCodeBoxEx(codebox, request, req_size, res_size, callback, context);
}

VOID XIGNAPI RegisterCallback(XigncodeCallbackT Callback, void *Context)
{
	Xclio_RegisterCallback(Callback, Context);
}

BOOL XIGNAPI SendCommandVa(unsigned int cid, va_list ap)
{
	return Xclio_SendCommandVa(cid, ap);
}

unsigned int XIGNAPI QueryFunction(void** Address, _XclioFid Fid)
{
	switch (Fid)
	{
		case XclioFidSysEnterA:
			*Address = SysEnterA;
			break;

		case XclioFidSysEnterW:
			*Address = SysEnterW;
			break;

		case XclioFidSysExit:
			*Address = SysExit;
			break;

		case XclioFidInit:
			*Address = Init;
			break;

		case XclioFidCleanup:
			*Address = Cleanup;
			break;

		case XclioFidProbe:
			*Address = Probe;
			break;

		case XclioFidProbeEx:
			*Address = ProbeEx;
			break;

		case XclioFidCreateCodeBox:
			*Address = CreateCodeBox;
			break;

		case XclioFidCloseCodeBox:
			*Address = CloseCodeBox;
			break;

		case XclioFidProbeCodeBox:
			*Address = ProbeCodeBox;
			break;

		case XclioFidProbeCodeBoxEx:
			*Address = ProbeCodeBoxEx;
			break;

		case XclioFidRegisterCallback:
			*Address = RegisterCallback;
			break;

		case XclioFidSendCommandVa:
			*Address = SendCommandVa;
			break;

		default:
			Log("QueryFunction - Address: %08X, Fid: %08X\n", Address, Fid);
			return 0xE0010002;
	}

	return 0;
}