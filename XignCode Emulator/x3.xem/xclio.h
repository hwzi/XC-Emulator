#pragma once

#include "global.h"

#include "CCodeBox.hpp"
#include "CInfo.hpp"
#include "CProbeEx.hpp"
#include "CXLock.hpp"
#include "xdna.h"
#include "xpack.h"
#include "xpl.h"
#include "xst.h"
#include "log.h"

struct PACKET_LIST;

extern void Ordinal3(void(__stdcall *)(int, int, int));
extern BOOL CreateModuleLoader(PACKET_LIST *packetList);
extern void ZCE_Scan2(XPL_WRITER **ppwWriter, PACKET_LIST *packetList);
extern BOOL IsInitialized();
extern XPL_WRITER ** InitWriter(XPL_WRITER **dst, void *buf, uint size);

extern BOOL XIGNAPI Xclio_SysEnterA(const char *License, const char *Path, uint Flags);
extern BOOL XIGNAPI Xclio_SysEnterW(const wchar_t *License, const wchar_t *Path, uint Flags);
extern BOOL XIGNAPI Xclio_SysExit();
extern BOOL XIGNAPI Xclio_Init();
extern BOOL XIGNAPI Xclio_Cleanup();
extern BOOL XIGNAPI Xclio_Probe(const unsigned char *request, unsigned char *response, uint req_size);
extern BOOL XIGNAPI Xclio_ProbeEx(const unsigned char *request, uint req_size, ProbeCallbackT callback, void *context);
extern void * XIGNAPI Xclio_CreateCodeBox();
extern BOOL XIGNAPI Xclio_CloseCodeBox(void *CodeBox);
extern BOOL XIGNAPI Xclio_ProbeCodeBox(void *CodeBox, const unsigned char *request, void *response, uint res_size);
extern BOOL XIGNAPI Xclio_ProbeCodeBoxEx(void *CodeBox, const unsigned char *request, uint req_size, uint res_size, ProbeCallbackT Callback, void *Context);
extern VOID XIGNAPI Xclio_RegisterCallback(XigncodeCallbackT Callback, void *Context);
extern BOOL XIGNAPI Xclio_SendCommandVa(uint cid, va_list ap);