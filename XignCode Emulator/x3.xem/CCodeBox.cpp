#include "CCodeBox.hpp"

BOOL REUSABLE_BUFFER::Alloc(uint size)
{
	if (this->size < size)
	{
		this->Free();
		this->buf = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!this->buf)
		{
			this->requires = 0;
			this->size = 0;

			return FALSE;
		}
		this->size = size;
	}
	this->requires = size;

	return TRUE;
}

VOID REUSABLE_BUFFER::Free()
{
	if (this->buf)
	{
		VirtualFree(this->buf, 0, MEM_RELEASE);
		this->buf = 0;
		this->requires = 0;
		this->size = 0;
	}
}

// DATA
PACKET_DATA::PACKET_DATA()
{
	this->key = 0;
	this->buffer.buf = nullptr;
	this->buffer.requires = 0;
	this->buffer.size = 0;
	this->fnImported = NULL;
	this->pLoader = nullptr;
	this->hModule = NULL;
}

PACKET_DATA::~PACKET_DATA()
{
	this->buffer.Free();
}

BOOL PACKET_DATA::Read(XPL_READER *reader)
{
	this->bBufferLoaded = FALSE;
	if (reader->vfptr->GetIndex(reader) > reader->vfptr->GetSize(reader))
	{
		SetLastError(0xE0190220);

		return FALSE;
	}

	if (this->key != reader->vfptr->GetKey(reader))
	{
		int size = reader->vfptr->f24(reader);
		this->buffer.Alloc(size);
		this->value = 0;
		this->receivedPacket = 0;
		this->key = reader->vfptr->GetKey(reader);
	}

	if (reader->vfptr->GetIndex(reader) >= reader->vfptr->GetSize(reader))
	{
		if (reader->vfptr->GetIndex(reader) != reader->vfptr->GetSize(reader))
		{
			SetLastError(0xE0190221);

			return FALSE;
		}
		strcpy_s(this->szProcName, MAX_PATH, (const char *)reader->vfptr->GetDecryptedBuffer(reader));
	}
	else
	{
		if (reader->vfptr->GetR(reader) + reader->vfptr->GetO(reader) > this->buffer.requires)
		{
			Log("xclio:: PACKET INFO mi=%d, G=%08x I=%d S=%08x T=%d R=%d O=%d cd=%d\n",
				this->receivedPacket, reader->vfptr->GetKey(reader), reader->vfptr->GetIndex(reader),
				reader->vfptr->GetValue(reader), reader->vfptr->GetSize(reader), reader->vfptr->GetR(reader), reader->vfptr->GetO(reader), this->buffer.requires);

			SetLastError(0xE0190222);

			return FALSE;
		}

		memcpy((unsigned char *)this->buffer.buf + reader->vfptr->GetO(reader), reader->vfptr->GetDecryptedBuffer(reader), reader->vfptr->GetR(reader));

		Log("F i=%d G=%08x I=%d S=%08x T=%d C=%08x\n",
			this->receivedPacket, reader->vfptr->GetKey(reader), reader->vfptr->GetIndex(reader),
			reader->vfptr->GetValue(reader), reader->vfptr->GetSize(reader), pXstImport->get_hash((uint *)reader->vfptr->GetDecryptedBuffer(reader), reader->vfptr->GetR(reader)));
	}

	if (this->receivedPacket == reader->vfptr->GetSize(reader))
		this->bBufferLoaded = TRUE;

	this->value ^= reader->vfptr->GetValue(reader);
	this->receivedPacket++;

	return TRUE;
}

BOOL PACKET_DATA::Compare(XPL_READER *reader)
{
	return memcmp(
		(unsigned char *)this->buffer.buf + reader->vfptr->GetO(reader),
		reader->vfptr->GetDecryptedBuffer(reader),
		reader->vfptr->GetR(reader)) == 0;
}

BOOL PACKET_DATA::AlwaysFalse()
{
	return FALSE;
}

BOOL PACKET_DATA::IsBufferReady()
{
	return this->key && this->bBufferLoaded;
}

BOOL PACKET_DATA::Load(MODULE_LOADER *pLoader)
{
	if (!pLoader)
		return FALSE;

	if (this->pLoader)
		this->Unload();

	if (pLoader->vfptr->XLoadLibrary(pLoader, &this->hModule, this->buffer.buf, this->buffer.requires) < 0 || !this->hModule)
		return FALSE;

	this->fnImported = pLoader->vfptr->XGetProcAddress(pLoader, this->hModule, this->szProcName);
	if (!fnImported)
	{
		pLoader->vfptr->XFreeLibrary(pLoader, this->hModule);
		this->hModule = NULL;

		return FALSE;
	}
	this->pLoader = pLoader;

	return TRUE;
}

BOOL PACKET_DATA::Unload()
{
	if (!this->hModule)
		return FALSE;

	this->pLoader->vfptr->XFreeLibrary(this->pLoader, this->hModule);
	this->fnImported = NULL;
	this->hModule = NULL;

	this->pLoader->vfptr->baseProvider.DecInstance(this->pLoader);

	return TRUE;
}

FARPROC PACKET_DATA::GetProcAddress(LPCSTR lpProcName)
{
	return this->pLoader->vfptr->XGetProcAddress(this->pLoader, this->hModule, lpProcName);
}

FARPROC PACKET_DATA::GetImportedF()
{
	return this->fnImported;
}

uint PACKET_DATA::GetValue()
{
	return this->value;
}

void PACKET_DATA::UpdateKey(uint key)
{
	this->key = key;
}

uint PACKET_DATA::GetKey()
{
	return this->key;
}

uint PACKET_DATA::GetSignature()
{
	if (!this->IsBufferReady())
		return 0;

	return *((uint *)this->buffer.buf);
}

HMODULE PACKET_DATA::GetXModuleHandle()
{
	return this->hModule;
}

uint * PACKET_DATA::GetBuffer()
{
	return (uint *)this->buffer.buf;
}

uint PACKET_DATA::GetBufferSize()
{
	return this->buffer.requires;
}
// DATA END

// LIST
PACKET_LIST::PACKET_LIST()
{
	this->index = 0;
}

BOOL PACKET_LIST::Read(XPL_READER *reader)
{
	PACKET_DATA *pPacketData;

	// match
	pPacketData = this->aPacketData;
	for (int i = 0; i < 3; i++)
	{
		if (pPacketData->key == reader->vfptr->GetKey(reader))
			return pPacketData->Read(reader);

		pPacketData++;
	}

	// not used
	pPacketData = this->aPacketData;
	for (int i = 0; i < 3; i++)
	{
		if (pPacketData->key == 0)
			return pPacketData->Read(reader);

		pPacketData++;
	}

	SetLastError(0xE0190223);

	return FALSE;
}

BOOL PACKET_LIST::Compare(XPL_READER *reader)
{
	return this->aPacketData[this->index].Compare(reader);
}

BOOL PACKET_LIST::AlwaysFalse()
{
	return this->aPacketData[this->index].AlwaysFalse();
}

BOOL PACKET_LIST::IsBufferReady()
{
	PACKET_DATA *pPacketData = this->aPacketData;

	for (int i = 0; i < 3; i++)
	{
		if (pPacketData->IsBufferReady())
		{
			this->index = i;

			return TRUE;
		}

		pPacketData++;
	}

	return FALSE;
}

BOOL PACKET_LIST::Load(MODULE_LOADER *pLoader)
{
	return this->aPacketData[this->index].Load(pLoader);
}

BOOL PACKET_LIST::Unload()
{
	return this->aPacketData[this->index].Unload();
}

FARPROC PACKET_LIST::GetProcAddress(LPCSTR lpProcName)
{
	return this->aPacketData[this->index].GetProcAddress(lpProcName);
}

FARPROC PACKET_LIST::GetImportedF()
{
	return this->aPacketData[this->index].GetImportedF();
}

uint PACKET_LIST::GetValue()
{
	return this->aPacketData[this->index].GetValue();
}

void PACKET_LIST::UpdateKey(uint key)
{
	this->aPacketData[this->index].UpdateKey(key);
}

uint PACKET_LIST::GetKey()
{
	return this->aPacketData[this->index].GetKey();
}

uint PACKET_LIST::GetSignature()
{
	return this->aPacketData[this->index].GetSignature();
}

HMODULE PACKET_LIST::GetXModuleHandle()
{
	return this->aPacketData[this->index].GetXModuleHandle();
}

uint * PACKET_LIST::GetBuffer()
{
	return this->aPacketData[this->index].GetBuffer();
}

uint PACKET_LIST::GetBufferSize()
{
	return this->aPacketData[this->index].GetBufferSize();
}
// LIST END

// CodeBox
// sub_100210FA
CCodeBox::CCodeBox()
{
	InitializeCriticalSection(&m_CriticalSection);

	// off_1009E6D4 vfptr for the list
}

CCodeBox::~CCodeBox()
{
	DeleteCriticalSection(&m_CriticalSection);
}

uint CCodeBox::UpdateValue(uint key, uint value)
{
	auto it = m_mData.find(key);
	if (it == m_mData.end())
	{
		// key not found
		m_mData.insert(std::make_pair(key, value));
		return value;
	}

	// update value
	it->second ^= value;

	return it->second;
}

// sub_1002157E k
BOOL CCodeBox::HandleUnk(XPL_READER *reader, void *res, uint res_size)
{
	PACKET_LIST		*packetList;
	XPL_WRITER		*writer;
	BOOL			result = FALSE;

	packetList = &m_aPacket[2];
	EnterCriticalSection(&m_CriticalSection);

	InitWriter(&writer, res, res_size);
	if (!writer)
	{
		LeaveCriticalSection(&m_CriticalSection);

		return FALSE;
	}

	if (packetList->IsBufferReady())
	{
		Ordinal3((void(__stdcall *)(int, int, int))packetList->GetProcAddress((LPCSTR)3));
		packetList->Unload();
		packetList->UpdateKey(0);
	}

	if (packetList->Read(reader) && !packetList->AlwaysFalse() && packetList->IsBufferReady())
	{
		if (CreateModuleLoader(packetList))
		{
			writer->vfptr->f0c(writer, 1);
			writer->vfptr->WriteValue(writer, packetList->GetValue());
			writer->vfptr->WriteKey(writer, packetList->GetKey());
			*writer->vfptr->GetRealBuffer(writer) = 0;
			result = TRUE;
		}
	}
	writer->vfptr->DecInstance(writer);
	LeaveCriticalSection(&m_CriticalSection);

	return result;
}

// sub_100216C0
BOOL CCodeBox::HandleNCB(XPL_READER *reader, void *res, uint res_size)
{
	XPL_WRITER	*writer;
	PACKET_LIST	*packetList;
	BOOL		result = FALSE;

	packetList = &m_aPacket[1];

	EnterCriticalSection(&m_CriticalSection);

	InitWriter(&writer, res, res_size);
	if (!writer)
	{
		LeaveCriticalSection(&m_CriticalSection);

		return FALSE;
	}

	if (!packetList->Read(reader))
		Log("xclio:: ncb fill error ge = %08x\n", GetLastError());
	else if (!packetList->AlwaysFalse() && packetList->IsBufferReady())
	{
		if (CreateModuleLoader(packetList))
		{
			void(__stdcall * fnImported)(void *, int) = (void(__stdcall *)(void *, int))packetList->GetImportedF();

			if (fnImported)
			{
				static auto callback = []() -> uint
				{
					return 0;
				};

				uint *v15 = writer->vfptr->GetRealBuffer(writer);
				v15[0] = 0;
				v15[1] = (uint)&callback;

				fnImported(writer->vfptr->GetRealBuffer(writer), writer->vfptr->GetRealSize(writer));
				packetList->Unload();
				writer->vfptr->f0c(writer, 1);
				writer->vfptr->WriteValue(writer, packetList->GetValue());
				writer->vfptr->WriteKey(writer, packetList->GetKey());
				packetList->UpdateKey(0);
				result = TRUE;
			}
		}
	}

	writer->vfptr->DecInstance(writer);
	LeaveCriticalSection(&m_CriticalSection);

	return result;
}

// sub_10021918
BOOL CCodeBox::HandleZCE(XPL_READER *reader, void *res, uint res_size)
{
	XPL_WRITER	*writer;
	PACKET_LIST *packetList;
	BOOL		result = FALSE;
	INT			prop;

	packetList = &m_aPacket[0];
	EnterCriticalSection(&m_CriticalSection);

	InitWriter(&writer, res, res_size);
	if (!writer)
	{
		LeaveCriticalSection(&m_CriticalSection);

		return FALSE;
	}

	if (!packetList->IsBufferReady())
	{
		if (!packetList->Read(reader))
			Log("xclio:: zce fill error ge = %08x\n", GetLastError());
		else if (packetList->AlwaysFalse())
			Log("ZCE IS ERROR\n");
		else if (packetList->IsBufferReady())
		{
			Log("ZCE COMPLETE\n");

			if (!CreateModuleLoader(packetList))
				Log("xclio:: zce load fail, GE=%08x\n", GetLastError());
			else
			{
				writer->vfptr->f0c(writer, 1);
				writer->vfptr->WriteValue(writer, packetList->GetValue());
				writer->vfptr->WriteKey(writer, packetList->GetKey());
				Xdna_getData(L"{E6B6CBA2-FC19-47f4-9D1D-AA8588175786}", &prop, 4, 3);

				if (prop == 3)
					ZCE_Scan2(&writer, packetList);	// zce.dll Scan2
				else if (prop == 2)
					*writer->vfptr->GetRealBuffer(writer) = 0;

				result = TRUE;
			}
		}
	}
	else
	{
		// flash packet if flag does not contain 0x8000
		if (reader->vfptr->f38(reader) & 0x8000)
		{
			if (reader->vfptr->GetIndex(reader) != reader->vfptr->GetSize(reader)) 
				this->UpdateValue(reader->vfptr->GetKey(reader), reader->vfptr->GetValue(reader)); // XOR VALUE
			else
			{
				writer->vfptr->WriteValue(writer, this->UpdateValue(reader->vfptr->GetKey(reader), reader->vfptr->GetValue(reader)));
				writer->vfptr->WriteKey(writer, reader->vfptr->GetKey(reader));
				writer->vfptr->f0c(writer, 1);

				// erase by key
				m_mData.erase(reader->vfptr->GetKey(reader));
				ZCE_Scan2(&writer, packetList);
				// if (writer)
				// writer->vfptr->DecInstance(writer);
				result = TRUE;
			}
		}
		else
		{
			writer->vfptr->WriteValue(writer, reader->vfptr->GetValue(reader));
			writer->vfptr->WriteKey(writer, reader->vfptr->GetKey(reader));
			writer->vfptr->f10(writer, 1);

			if (packetList->Compare(reader))
				ZCE_Scan2(&writer, packetList);
			else
			{
				Log("ZCE COMPLETE RESEND REPLY\n");

				packetList->Unload();
				packetList->UpdateKey(0);
				*writer->vfptr->GetRealBuffer(writer) = 0xFFFFFFFF;
			}
			// if (writer)
			// writer->vfptr->DecInstance(writer);
			result = TRUE;
		}
	}

	writer->vfptr->DecInstance(writer);
	LeaveCriticalSection(&m_CriticalSection);

	return result;
}

// sub_10021DFF
int CCodeBox::HandlePacket(XPL_READER *reader, void *res, uint res_size)
{
	WCHAR *pszErr, *pszTemp;
	WCHAR szErr[256];

	switch (reader->vfptr->GetType(reader))
	{
		case 1:
		{
			// ncb.dll (jfz.dll)
			return this->HandleNCB(reader, res, res_size) == 0;
		}
		case 2:
		{
			// zce.dll
			return this->HandleZCE(reader, res, res_size) == 0;
		}
		case 3:
		{
			// ?
			return this->HandleUnk(reader, res, res_size) == 0;
		}
		case 4:
		{
			// Error Msg
			pszErr = (WCHAR *)reader->vfptr->GetDecryptedBuffer(reader);
			Log("xclio:: ProbeTerm %ls\n", pszErr);

			if (wcsncmp(pszErr, L"ZCE", 3) == 0)
			{
				// MM.CMOD SvrCodeDetected 
				// IF.CMOD SvrCodeDetected 

				// skip "ZCE "
				pszTemp = wcschr(pszErr + 4, ':');
				if (pszTemp)
					*pszTemp = '\0'; // cut

				Log("CMOD SvrCodeDetected %ls\n", pszErr + 4);
			}
			else
			{
				if (!wcsncmp(pszErr, L"ERR", 3))
					pszTemp = L"{65C78797-3868-4d84-8C58-E92880B2AAFA}";
				else if (!wcsncmp(pszErr, L"TME", 3))
					pszTemp = L"{320C0CDF-4F64-49ac-A33F-E708DED89149}";
				else
					pszTemp = L"{46E57FA1-2806-4702-B96B-EEF5C87D36C8}";
			}
			return 1;
		}
		default:
		{
			memset(szErr, 0, sizeof(szErr));
			reader->vfptr->f34(reader, szErr, sizeof(szErr));
			Log("Packet Type Unknown %ls\n", szErr);
			Log("PacketError: undefined\n");

			return 2;
		}
	}
}
// CTX END