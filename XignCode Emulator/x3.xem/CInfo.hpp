#pragma once

#include "global.h"

#include "xdna.h"
#include "log.h"

typedef struct _ZCE_ID
{
	union
	{
		unsigned char buffer[16];
		struct
		{
			uint			a;
			unsigned short	b;
			unsigned short	c;
			unsigned char	d;
			unsigned char	e;
			unsigned char	f;
			unsigned char	g;
			unsigned char	h;
			unsigned char	i;
			unsigned char	j;
			unsigned char	k;
		};
	};
} ZCE_ID;

struct CInfo
{
	char m_szLicense[16];
	wchar_t m_wszLicense[16];
	unsigned int m_uRevision;
	void *m_lpCallbackContext;
	XigncodeCallbackT m_fnCallback;
	ZCE_ID m_adaptersHash;

	BOOL fInitialized;

private:
	CInfo();
	~CInfo() = default;

public:
	CInfo(const CInfo&) = delete;
	CInfo& operator=(const CInfo&) = delete;
	CInfo(CInfo&&) = delete;
	CInfo& operator=(CInfo&&) = delete;

public:
	static CInfo& getInstance()
	{
		static CInfo instance;
		return instance;
	}

public:
	BOOL GrabInfo(__in LPCWSTR lpcszXmagPath);
	LPCSTR GetLicenseA();
	DWORD GetRevision();
	ZCE_ID *GetAdaptersHash();

	void SetCallbackInfo(XigncodeCallbackT fnCallback, void *lpCallbackContext);
};