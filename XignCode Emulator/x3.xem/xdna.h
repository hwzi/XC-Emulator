#pragma once

#include "global.h"

#include "log.h"
#include "xpack.h"
#include "xst.h"

#pragma pack(push, 1)
typedef struct _RSA_FILE_HEADER
{
	CHAR	name[30];
	uint	signature;
	uint	bufSize;
	uint	originSize;
	ubyte	rsaKeyLen;
	ubyte	start[5];
} RSA_FILE_HEADER;

typedef struct _XDNA_PROPERTY
{
	ubyte	type;
	ubyte	keySize;
	uint	dataSize;
	ubyte	buf[1];
} XDNA_PROPERTY, *PXDNA_PROPERTY, *LPXDNA_PROPERTY;
#pragma pack(pop)

typedef struct _XDNA_CTX
{
	uint	type;
	uint	size;
	WCHAR	key[128];
	void	*data;
} XDNA_CTX, *PXDNA_CTX, *LPXDNA_CTX;

extern BOOL Xdna_Init(__in LPCWSTR lpFile);
extern DWORD Xdna_Clear();
extern BOOL Xdna_getData(__in LPCWSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize);
extern BOOL Xdna_getData(__in LPCWSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize, __in DWORD dwDefaultKey);