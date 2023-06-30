#pragma once

#include "global.h"

#include "xclio.h"
#include "xdna.h"
#include "xst.h"
#include "log.h"

struct REUSABLE_BUFFER
{
	void *buf;
	uint requires;
	uint size;

public:
	BOOL Alloc(uint size);
	VOID Free();
};

struct PACKET_DATA
{
	uint			value;
	uint			receivedPacket;
	uint			key;
	REUSABLE_BUFFER	buffer;
	BOOL			bBufferLoaded;
	CHAR			szProcName[MAX_PATH];
	FARPROC			fnImported;
	MODULE_LOADER	*pLoader;
	HMODULE			hModule;

public:
	PACKET_DATA();
	~PACKET_DATA();

public:
	// off_1009E694
	BOOL		Read(XPL_READER *reader);
	BOOL		Compare(XPL_READER *reader);
	BOOL		AlwaysFalse();
	BOOL		IsBufferReady();
	BOOL		Load(MODULE_LOADER *);
	BOOL		Unload();
	FARPROC		GetProcAddress(LPCSTR lpProcName);
	FARPROC		GetImportedF();
	uint		GetValue();
	void		UpdateKey(uint key);
	uint		GetKey();
	uint		GetSignature();
	HMODULE		GetXModuleHandle();
	uint *		GetBuffer();
	uint		GetBufferSize();
};

struct PACKET_LIST
{
	PACKET_DATA		aPacketData[3];
	uint			index;

public:
	PACKET_LIST();

public:
	BOOL		Read(XPL_READER *);
	BOOL		Compare(XPL_READER *);
	BOOL		AlwaysFalse();
	BOOL		IsBufferReady();
	BOOL		Load(MODULE_LOADER *);
	BOOL		Unload();
	FARPROC 	GetProcAddress(LPCSTR lpProcName);
	FARPROC		GetImportedF();
	uint		GetValue();
	void		UpdateKey(uint key);
	uint		GetKey();
	uint		GetSignature();
	HMODULE		GetXModuleHandle();
	uint *		GetBuffer();
	uint		GetBufferSize();

};

struct CCodeBox
{
	std::map<uint, uint>	m_mData;
	CRITICAL_SECTION		m_CriticalSection;
	PACKET_LIST				m_aPacket[3];

public:
	CCodeBox();
	~CCodeBox();

public:
	uint	UpdateValue(uint key, uint value);
	BOOL	HandleUnk(XPL_READER *reader, void *res, uint res_size);
	BOOL	HandleNCB(XPL_READER *reader, void *res, uint res_size);
	BOOL	HandleZCE(XPL_READER *reader, void *res, uint res_size);
	int		HandlePacket(XPL_READER *reader, void *res, uint res_size);
};