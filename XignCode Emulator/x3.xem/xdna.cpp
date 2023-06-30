#include "xdna.h"

DWORD dwXdnaInstance = 0;
CRITICAL_SECTION CriticalSection;
std::list<LPXDNA_CTX> lProperties;

rsa_ctx **RsaPublicDecrypt(rsa_ctx **rsa, void *src, uint ssize, void *key, uint keySize, void **dst, uint *dsize)
{
	int err;

	err = pXstImport->RsaCreate(rsa);
	if (err < 0)
		throw err;

	err = pXstImport->RsaSetPublicKey(*rsa, key, keySize);
	if (err < 0)
	{
		pXstImport->RsaClose(*rsa);
		throw err;
	}

	err = pXstImport->RsaPublicDecrypt(*rsa, src, ssize, dst, dsize);
	if (err < 0)
	{
		pXstImport->RsaClose(*rsa);
		throw err;
	}

	return rsa;
}

XDNA_CTX * ReadProp(__in LPBYTE *lplpBuf)
{
	LPXDNA_CTX lpCTX = new XDNA_CTX;

	if (!lpCTX)
		return NULL;

	XDNA_PROPERTY *lpProp = (XDNA_PROPERTY *)*lplpBuf;

	MultiByteToWideChar(CP_UTF8, 0, (LPCCH)lpProp->buf, -1, lpCTX->key, 128);

	lpCTX->size = lpProp->dataSize;
	lpCTX->type = lpProp->type;
	lpCTX->data = malloc(lpProp->dataSize);

	if (!lpCTX->data)
	{
		delete lpCTX;

		return NULL;
	}

	memcpy(lpCTX->data, lpProp->buf + lpProp->keySize, lpCTX->size);
	*lplpBuf += lpProp->keySize + lpProp->dataSize + 6; // seek

	return lpCTX;
}

BOOL Xdna_Load(__in LPCWSTR lpFile)
{
	MODULE_LOADER *pLomxLoader;
	PACKED_FILE_CTX file;

	RSA_FILE_HEADER header;
	ubyte *spackedBuf, *rsaBuf;
	uint publicKeySize;
	rsa_ctx *rsa;
	ubyte *xdna, *xdnaTemp, *xdnaEnd;
	uint xdna_size;
	LPXDNA_CTX lpCTX;
	BOOL result;

	EnterCriticalSection(&CriticalSection);

	if (pXstImport->CreateProvider(LOADER_LOMX, &pLomxLoader) < 0)
	{
		LeaveCriticalSection(&CriticalSection);

		return FALSE;
	}

	result = FALSE;

	if (GetXFileInfo(lpFile, "xdna.xem", &file))
	{
		// RSA->
		memcpy(&header, file.buf, sizeof(RSA_FILE_HEADER));
		spackedBuf = (ubyte *)malloc(header.bufSize);

		if (spackedBuf)
		{
			publicKeySize = header.rsaKeyLen << 3;
			rsaBuf = (ubyte *)malloc(header.originSize);

			if (rsaBuf)
			{
				memcpy(spackedBuf, (unsigned char *)file.buf + sizeof(RSA_FILE_HEADER), header.bufSize);
				pXstImport->Unspack(rsaBuf, &header.originSize, spackedBuf, &header.bufSize, header.start, 5); // dst, dsize, src, ssize, data, dataSize

				// rsa_buf { rsa_public_key -> rsa_public_src }
				RsaPublicDecrypt(&rsa, rsaBuf + publicKeySize, header.originSize - publicKeySize,
					rsaBuf, publicKeySize, (void **)&xdna, &xdna_size);
				// <-RSA

				// read xdna.xem
				xdnaTemp = xdna;
				xdnaEnd = xdna + xdna_size;

				while (xdnaTemp < xdnaEnd)
				{
					lpCTX = ReadProp(&xdnaTemp);

					if (!lpCTX)
						break;

					lProperties.push_back(lpCTX);
				}
				result = TRUE;

				// RSA->
				// free
				if (xdna)
					pXstImport->RsaFreeBuffer(rsa, xdna);

				if (rsa)
					pXstImport->RsaClose(rsa);

				free(rsaBuf);
			}
			free(spackedBuf);
		}

		free(file.buf);
		// <-RSA
	}

	pLomxLoader->vfptr->baseProvider.DecInstance(pLomxLoader);
	LeaveCriticalSection(&CriticalSection);

	return result;
}

BOOL Xdna_getData(__in LPCWSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize)
{
	LPXDNA_CTX lpCTX;
	BOOL bResult;

	if (!lpDst)
		return FALSE;

	if (InterlockedCompareExchange(&dwXdnaInstance, 0, 0) == 0)
		return FALSE;

	EnterCriticalSection(&CriticalSection);

	bResult = FALSE;

	for (auto it = lProperties.begin(); it != lProperties.end(); it++)
	{
		lpCTX = *it;

		if (wcscmp(lpCTX->key, lpKey) == 0)
		{
			if (lpCTX->size <= dwSize)
			{
				memcpy(lpDst, lpCTX->data, lpCTX->size);
				bResult = TRUE;
			}
		}
	}

	LeaveCriticalSection(&CriticalSection);

	return bResult;
}

BOOL Xdna_getData(__in LPCWSTR lpKey, __out LPVOID lpDst, __in DWORD dwSize, __in DWORD dwDefaultKey)
{
	LPXDNA_CTX lpCTX;
	BOOL bResult;

	if (!lpDst)
		return FALSE;

	if (InterlockedCompareExchange(&dwXdnaInstance, 0, 0) == 0)
		return FALSE;

	EnterCriticalSection(&CriticalSection);

	bResult = FALSE;

	for (auto it = lProperties.begin(); it != lProperties.end(); it++)
	{
		lpCTX = *it;
		if (wcscmp(lpCTX->key, lpKey) == 0)
		{
			if (lpCTX->size <= dwSize)
			{
				memcpy(lpDst, lpCTX->data, lpCTX->size);
				bResult = TRUE;
			}
		}
	}

	if (!bResult && dwSize == 4)
	{
		*(DWORD*)lpDst = dwDefaultKey;
		lpCTX = new XDNA_CTX;
		lpCTX->type = 0;
		lpCTX->size = 4;
		lstrcpyW(lpCTX->key, lpKey);
		lpCTX->data = malloc(4);

		if (!lpCTX->data)
			delete lpCTX;
		else
		{
			memcpy(lpCTX->data, &dwDefaultKey, 4);
			lProperties.push_back(lpCTX);
			bResult = TRUE;
		}
	}

	LeaveCriticalSection(&CriticalSection);

	return bResult;
}

BOOL Xdna_Init(__in LPCWSTR lpFile)
{
	if (InterlockedIncrement(&dwXdnaInstance) == 1)
	{
		InitializeCriticalSection(&CriticalSection);

		return Xdna_Load(lpFile);
	}

	return TRUE;
}

DWORD Xdna_Clear()
{
	LPXDNA_CTX lpCTX;
	DWORD dwResult;
	
	if (InterlockedCompareExchange(&dwXdnaInstance, 0, 0) == 0)
	{
		// not init-ed yet
		return 0;
	}

	dwResult = InterlockedDecrement(&dwXdnaInstance);

	if (dwResult == 0)
	{
		DeleteCriticalSection(&CriticalSection);

		for (auto it = lProperties.begin(); it != lProperties.end(); it++)
		{
			lpCTX = *it;

			if (lpCTX->data)
				free(lpCTX->data);

			delete lpCTX;
		}

		lProperties.clear();
	}
	return dwResult;
}