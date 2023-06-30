#include "CInfo.hpp"

CInfo::CInfo()
{
	this->fInitialized = FALSE;
}

/*
// sub_1004D6C3
int sub_1004D6C3(wchar_t *dst, uint len, const wchar_t *License)
{
	unsigned char abHex[16];
	wchar_t szTemp[MAX_PATH];
	wchar_t szFileName[80];

	memset(szTemp, 0, sizeof(szTemp));

	pXstImport->AppendWideChar(szTemp, sizeof(szTemp), License);
	pXstImport->AppendWideChar(szTemp, sizeof(szTemp) * sizeof(wchar_t), L"SYSID_FILE_PATH");
	pXstImport->GetFileNameByLicense(szTemp, wcslen(szTemp) * sizeof(wchar_t), abHex);
	if (pXstImport->HexToWideChar(szFileName, sizeof(szFileName), abHex, 16, false) < 0)
	{
		lstrcpyW(szFileName, L"{60AB6364-9088-4cb3-AB4F-D8F51531DB2A}");
	}
	GetTempPathW(len, dst);
	pXstImport->AppendWideChar(dst, len * sizeof(wchar_t), szFileName);
	pXstImport->AppendWideChar(dst, len * sizeof(wchar_t), L".dll");

	printf("%ls\n", dst);

	return 0;
}

int sub_1004D858(const wchar_t *License)
{
	wchar_t szFileName[MAX_PATH];
	FILE *pFile;
	unsigned char buf[512];

	sub_1004D6C3(szFileName, sizeof(szFileName), License);
	_wfopen_s(&pFile, szFileName, L"wb");
	if (!pFile)
	{
		return 0xE0010004;
	}

	*(uint *)buf = 0x77225A69;
	memcpy(buf + 4, AdaptersHash.buffer, 16);

	std::string key("{41C96274-75F5-44af-93D8-5E7B164E00FF}");
	int error = pXstImport->Encrypt(buf, 512, key.c_str(), key.size(), buf, 512, RC4);
	if (error < 0)
	{
		fclose(pFile);
		return error;
	}

	if (fwrite(buf, 1, 512, pFile) != 512)
	{
		fclose(pFile);
		return 0xE0230038;
	}
	fclose(pFile);

	return 0;
}

int sub_1004D9FE(const wchar_t *License)
{
	wchar_t szFileName[MAX_PATH];
	FILE *pFile;
	unsigned char buf[512];
	errno_t err;

	sub_1004D6C3(szFileName, sizeof(szFileName), License);
	err = _wfopen_s(&pFile, szFileName, L"rb");
	if (err == 0)
	{
		return 0xE0010004;
	}

	if (fread(buf, 1, sizeof(buf), pFile) != sizeof(buf))
	{
		fclose(pFile);
		return 0xE0230032;
	}
	fclose(pFile);

	std::string key("{41C96274-75F5-44af-93D8-5E7B164E00FF}");
	uint error = pXstImport->Decrypt(buf, sizeof(buf), key.c_str(), key.size(), buf, sizeof(buf), RC4);
	if (error < 0)
		return error;

	// signature iZ"w
	if (*(uint *)buf != 0x77225A69)
		return 0xE0230039;

	memcpy(AdaptersHash.buffer, buf + 4, 16);

	return 0;
}

uint sub_10056E4B(unsigned char *data)
{
	ADAPTER_INFO_PROVIDER *pAdapterInfoProvider;
	ULONG ulOutBufLen;
	PIP_ADAPTER_INFO pAdapterInfo, pAdapterInfoTemp;
	DWORD dwRetVal;
	unsigned char buf[256];

	if (pXstImport->CreateProvider(ADAPTER_INFO, &pAdapterInfoProvider) < 0)
	{
		throw;
	}

	ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));

	if (pAdapterInfoProvider->vfptr->GetAdaptersInfo(pAdapterInfoProvider, pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
	}
	if ((dwRetVal = pAdapterInfoProvider->vfptr->GetAdaptersInfo(pAdapterInfoProvider, pAdapterInfo, &ulOutBufLen)) != NO_ERROR)
	{
		free(pAdapterInfo);
		pAdapterInfoProvider->vfptr->baseProvider.DecInstance(pAdapterInfoProvider);
		return dwRetVal | 0xE0FF0000;
	}

	pAdapterInfoTemp = pAdapterInfo;
	pXstImport->key_init(buf);
	while (pAdapterInfoTemp)
	{
		pXstImport->key_calc(buf, pAdapterInfoTemp->Address, pAdapterInfoTemp->AddressLength);
		pAdapterInfoTemp = pAdapterInfoTemp->Next;
	}
	pXstImport->key_get(buf, data);

	free(pAdapterInfo);
	pAdapterInfoProvider->vfptr->baseProvider.DecInstance(pAdapterInfoProvider);

	return 0;
}

int sub_10056FC4()
{
	int result;
	unsigned char v2[16];

	result = sub_10056E4B(v2);
	if (result >= 0)
	{
		memcpy(AdaptersHash.buffer, v2, 16);
		result = 0;
	}
	return result;
}

int sub_1004E084(const wchar_t *License)
{
	int result;

	result = sub_1004D9FE(License);	// read
	if (result < 0)
	{
		result = sub_10056FC4();	// get
		if (result >= 0)
		{
			sub_1004D858(License);	// write
			result = 0;
		}
	}
	return result;
}*/

BOOL CInfo::GrabInfo(__in LPCWSTR lpFile)
{
	HINTERNET hInternet, hFile;
	DWORD dwNumberOfBytesRead;
	DWORD dwRevHash;
	BOOL bResult;

	WCHAR szProtocol[128];
	WCHAR szServer[128];
	WCHAR szRoot[128];
	WCHAR szVersion[128];
	WCHAR szUrl[1024];

	// get data from xdna.xem
	if (!Xdna_Init(lpFile))
	{
		Log("Xdna_Init\n");

		return FALSE;
	}

	if (!Xdna_getData(L"UpdateProtocol", szProtocol, sizeof(szProtocol)))
	{
		lstrcpyW(szProtocol, L"http");
	}
	if (!Xdna_getData(L"UpdateServer", szServer, sizeof(szServer)))
	{
		Log("Xdna_getData UpdateServer\n");

		return FALSE;
	}
	if (!Xdna_getData(L"UpdateRoot", szRoot, sizeof(szRoot)))
	{
		Log("Xdna_getData UpdateRoot\n");

		return FALSE;
	}
	if (!Xdna_getData(L"UpdateVersion", szVersion, sizeof(szVersion)))
	{
		Log("Xdna_getData UpdateVersion\n");

		return FALSE;
	}
	if (!Xdna_getData(L"License", m_wszLicense, sizeof(m_wszLicense)))
	{
		Log("Xdna_getData License\n");

		return FALSE;
	}
	WideCharToMultiByte(CP_ACP, 0, m_wszLicense, -1, m_szLicense, 16, NULL, NULL);

	Xdna_Clear();

	wsprintf(szUrl, L"%ls://%ls%ls/%ls%ls/%ls", szProtocol, szServer, szRoot, m_wszLicense, L"/List", szVersion);

	Log("Download Url : %ls\n", szUrl);

	bResult = FALSE;

	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet != NULL)
	{
		hFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, NULL);
		if (hFile != NULL)
		{
			bResult = InternetReadFile(hFile, &dwRevHash, 4, &dwNumberOfBytesRead);
			InternetCloseHandle(hFile);

			if (bResult && dwNumberOfBytesRead == 4)
			{
				m_uRevision = dwRevHash ^ 0x19810118;
				fInitialized = TRUE;
			}
		}
		InternetCloseHandle(hInternet);
	}

	memset(m_adaptersHash.buffer, 0, 16);

	return bResult;
}

LPCSTR CInfo::GetLicenseA()
{
	if (!fInitialized)
		throw;

	return m_szLicense;
}

DWORD CInfo::GetRevision()
{
	if (!fInitialized)
		throw;

	return m_uRevision;
}

ZCE_ID *CInfo::GetAdaptersHash()
{
	if (!fInitialized)
		throw;

	return &m_adaptersHash;
}

void CInfo::SetCallbackInfo(XigncodeCallbackT fnCallback, void *lpCallbackContext)
{
	InterlockedExchange(reinterpret_cast<DWORD*>(&m_fnCallback), reinterpret_cast<DWORD>(fnCallback));
	InterlockedExchange(reinterpret_cast<DWORD*>(&m_lpCallbackContext), reinterpret_cast<DWORD>(lpCallbackContext));
}