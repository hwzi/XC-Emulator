#include "stdafx.h"

#include "xigncode.h"
#include "utils.h"
#include "xez.h"
#include "xkaga.h"

#include <list>
#include <Psapi.h>
#include <string>
#include <winternl.h>

#define DEBUG_MODE

LPVOID lpHookAddress;
CRITICAL_SECTION CriticalSection;

VOID Detour__GetVersion()
{
	static decltype(&GetVersion) _GetVersion = reinterpret_cast<decltype(&GetVersion)>(GetProcAddress(
		GetModuleHandle(TEXT("KERNELBASE")), "GetVersion"));

	decltype(&GetVersion) GetVersion__Hook = []() -> DWORD
	{
		HMODULE hModule;
		if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<TCHAR*>(_ReturnAddress()), &hModule))
			return 0; // version < 5

		return _GetVersion();
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_GetVersion), GetVersion__Hook);
}

VOID Detour__GetWindowThreadProcessId()
{
	static decltype(&GetWindowThreadProcessId) _GetWindowThreadProcessId = GetWindowThreadProcessId;

	decltype(&GetWindowThreadProcessId) GetWindowThreadProcessId__Hook = [](
		_In_ HWND hWnd,
		_Out_opt_ LPDWORD lpdwProcessId
		) -> DWORD
	{
		HMODULE hModule;

		if (lpdwProcessId)
		{
			if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<TCHAR*>(_ReturnAddress()), &hModule))
			{
				*lpdwProcessId = GetCurrentProcessId();

				return NULL;
			}
		}

		return _GetWindowThreadProcessId(hWnd, lpdwProcessId);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_GetWindowThreadProcessId), GetWindowThreadProcessId__Hook);
}

VOID Detour__CreateSemaphoreW()
{
	static decltype(&CreateSemaphoreW) _CreateSemaphoreW = CreateSemaphoreW;

	decltype(&CreateSemaphoreW) CreateSemaphoreW__Hook = [](
		_In_opt_ LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
		_In_     LONG lInitialCount,
		_In_     LONG lMaximumCount,
		_In_opt_ LPCWSTR lpName) -> HANDLE
	{
		if (lpName)
		{
			// if (lstrcmpW(lpName, L"Global\\448d43a1ca57e7c7a80ee1bf840b2f91") == 0)
			// lpName = NULL;

			HMODULE hModule;

			if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<TCHAR*>(_ReturnAddress()), &hModule))
			{
				lpName = NULL;
			}
		}

		return _CreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_CreateSemaphoreW), CreateSemaphoreW__Hook);
}

VOID Detour__NtOpenProcess()
{
	typedef struct _CLIENT_ID
	{
		DWORD UniqueProcess;
		DWORD UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef NTSTATUS(NTAPI * pfnNtOpenProcess)(
		_Out_    PHANDLE            ProcessHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID			ClientId);

	static pfnNtOpenProcess _NtOpenProcess = reinterpret_cast<pfnNtOpenProcess>(GetProcAddress(
		GetModuleHandle(TEXT("ntdll")), "NtOpenProcess"));

	pfnNtOpenProcess NtOpenProcess__Hook = [](
		_Out_    PHANDLE            ProcessHandle,
		_In_     ACCESS_MASK        DesiredAccess,
		_In_     POBJECT_ATTRIBUTES ObjectAttributes,
		_In_opt_ PCLIENT_ID			ClientId) -> NTSTATUS
	{
		if (ClientId->UniqueProcess != GetCurrentProcessId())
			return STATUS_ACCESS_DENIED;

		return _NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_NtOpenProcess), NtOpenProcess__Hook);
}

VOID Detour__NtQuerySystemInformation()
{
	typedef NTSTATUS(NTAPI * pfnNtQuerySystemInformation)(
		_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_   PVOID                    SystemInformation,
		_In_      ULONG                    SystemInformationLength,
		_Out_opt_ PULONG                   ReturnLength);

	static pfnNtQuerySystemInformation _NtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(GetProcAddress(
		GetModuleHandle(TEXT("ntdll")), "NtQuerySystemInformation"));

	pfnNtQuerySystemInformation NtQuerySystemInformation__Hook = [](
		_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_   PVOID                    SystemInformation,
		_In_      ULONG                    SystemInformationLength,
		_Out_opt_ PULONG                   ReturnLength) -> NTSTATUS
	{
		HMODULE hModule;
		NTSTATUS ret;

		// SystemCurrentTimeZoneInformation
		if (SystemInformationClass == (SYSTEM_INFORMATION_CLASS)0x2C)
			return STATUS_ACCESS_DENIED;

		ret = _NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		if (SystemInformationClass == SystemProcessInformation && ret == STATUS_SUCCESS)
		{
			if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<TCHAR*>(_ReturnAddress()), &hModule))
			{
				if (SystemInformation)
					((PSYSTEM_PROCESS_INFORMATION)SystemInformation)->NextEntryOffset = 0;
			}
		}

		return ret;
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_NtQuerySystemInformation), NtQuerySystemInformation__Hook);
}

VOID Detour__NtQueryInformationProcess()
{
	typedef NTSTATUS(NTAPI * pfnNtQueryInformationProcess)(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength);

	static pfnNtQueryInformationProcess _NtQueryInformationProcess = reinterpret_cast<pfnNtQueryInformationProcess>(GetProcAddress(
		GetModuleHandle(TEXT("ntdll")), "NtQueryInformationProcess"));

	pfnNtQueryInformationProcess  NtQueryInformationProcess__Hook = [](
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength) -> NTSTATUS
	{
		HMODULE hModule;
		if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<TCHAR*>(_ReturnAddress()), &hModule))
		{
			if (ProcessInformationClass == ProcessWow64Information || ProcessInformationClass == ProcessBasicInformation)
			{
				if (GetProcessId(ProcessHandle) == GetCurrentProcessId())
					return STATUS_UNSUCCESSFUL;
			}
		}

		return _NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
			ProcessInformationLength, ReturnLength);;
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_NtQueryInformationProcess), NtQueryInformationProcess__Hook);
}

VOID Detour__NtWow64QueryInformationProcess64()
{
	typedef NTSTATUS(NTAPI * pfnNtWow64QueryInformationProcess64)(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength);

	static pfnNtWow64QueryInformationProcess64 _NtWow64QueryInformationProcess64 = reinterpret_cast<pfnNtWow64QueryInformationProcess64>(GetProcAddress(
		GetModuleHandle(TEXT("ntdll")), "NtWow64QueryInformationProcess64"));

	pfnNtWow64QueryInformationProcess64  NtWow64QueryInformationProcess64__Hook = [](
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength) -> NTSTATUS
	{
		HMODULE hModule;

		if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<TCHAR*>(_ReturnAddress()), &hModule))
		{
			if (ProcessInformationClass == ProcessBasicInformation)
			{
				if (GetProcessId(ProcessHandle) == GetCurrentProcessId())
					return STATUS_UNSUCCESSFUL;
			}
		}

		return _NtWow64QueryInformationProcess64(ProcessHandle, ProcessInformationClass, ProcessInformation,
			ProcessInformationLength, ReturnLength);;
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_NtWow64QueryInformationProcess64), NtWow64QueryInformationProcess64__Hook);
}

VOID Detour__NtOpenThread()
{
	typedef struct _CLIENT_ID
	{
		DWORD UniqueProcess;
		DWORD UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef NTSTATUS(NTAPI * pfnNtOpenThread)(
		_Out_ PHANDLE            ThreadHandle,
		_In_  ACCESS_MASK        DesiredAccess,
		_In_  POBJECT_ATTRIBUTES ObjectAttributes,
		_In_  PCLIENT_ID         ClientId);

	static pfnNtOpenThread _NtOpenThread = reinterpret_cast<pfnNtOpenThread>(GetProcAddress(
		GetModuleHandle(TEXT("ntdll")), "NtOpenThread"));

	pfnNtOpenThread NtOpenThread__Hook = [](
		_Out_ PHANDLE            ThreadHandle,
		_In_  ACCESS_MASK        DesiredAccess,
		_In_  POBJECT_ATTRIBUTES ObjectAttributes,
		_In_  PCLIENT_ID         ClientId) -> NTSTATUS
	{
		if (DesiredAccess & THREAD_ALL_ACCESS)
			DesiredAccess &= ~(THREAD_SET_THREAD_TOKEN);

		DesiredAccess &= ~(THREAD_QUERY_INFORMATION);

		return _NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_NtOpenThread), NtOpenThread__Hook);
}

VOID Detour__WideCharToMultiByte()
{
	static decltype(&WideCharToMultiByte) _WideCharToMultiByte = WideCharToMultiByte;

	decltype(&WideCharToMultiByte) WideCharToMultiByte__Hook = [](
		_In_ UINT CodePage,
		_In_ DWORD dwFlags,
		_In_NLS_string_(cchWideChar) LPCWCH lpWideCharStr,
		_In_ int cchWideChar,
		_Out_writes_bytes_to_opt_(cbMultiByte, return) LPSTR lpMultiByteStr,
		_In_ int cbMultiByte,
		_In_opt_ LPCCH lpDefaultChar,
		_Out_opt_ LPBOOL lpUsedDefaultChar) -> int
	{

		const LPCWSTR sz_xkaga = L"xkaga.xem => ";
		const LPCWSTR sz_xez = L"xez.xem => ";

		LPCWSTR lpsz;
		PIMAGE_DOS_HEADER pImageDosHeader;
		PIMAGE_NT_HEADERS pImageNtHeaders;

		int nBytes = _WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr,
			cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

		if (CodePage == CP_UTF8 && cbMultiByte == 239)
		{
#ifdef DEBUG_MODE
			if (wcsstr(lpWideCharStr, L"DRIVER") == NULL &&
				wcsstr(lpWideCharStr, L"PROCESS") == NULL &&
				wcsstr(lpWideCharStr, L"MODULE") == NULL)
			{
				HANDLE hFile = CreateFile(TEXT("xigncode.txt"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
					OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				DWORD dwNumberOfBytesWritten;

				if (hFile != INVALID_HANDLE_VALUE)
				{
					SetFilePointer(hFile, 0, NULL, FILE_END);
					WriteFile(hFile, lpMultiByteStr, nBytes, &dwNumberOfBytesWritten, NULL);
					WriteFile(hFile, "\r\n", strlen("\r\n"), &dwNumberOfBytesWritten, NULL);
					CloseHandle(hFile);
				}
				printf("%ws\n", lpWideCharStr);
			}
#endif

			if (!xkaga_xem)
			{
				lpsz = wcsstr(lpWideCharStr, sz_xkaga);

				if (lpsz)
				{
					xkaga_xem = (HMODULE)wcstoul(lpsz + lstrlenW(sz_xkaga), NULL, 16);
					pImageDosHeader = PIMAGE_DOS_HEADER(xkaga_xem);

					if (pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
					{
						// xkaga.xem thank you very much
						pImageNtHeaders = PIMAGE_NT_HEADERS((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew);
						if (pImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
						{
							xkaga_size = pImageNtHeaders->OptionalHeader.SizeOfCode;

							printf("xkaga : %08X\n", pImageDosHeader);
						}
						else
						{
							printf("ERROR xkaga.xem\n");
						}
					}
					else
					{
						printf("ERROR xkaga.xem\n");
					}
				}
			}

			if (!xez_xem)
			{
				lpsz = wcsstr(lpWideCharStr, sz_xez);

				if (lpsz)
				{
					xez_xem = (HMODULE)wcstoul(lpsz + lstrlenW(sz_xez), NULL, 16);
					pImageDosHeader = PIMAGE_DOS_HEADER(xez_xem);

					if (pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
					{
						pImageNtHeaders = PIMAGE_NT_HEADERS((DWORD)pImageDosHeader + pImageDosHeader->e_lfanew);
						if (pImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
							xez_size = pImageNtHeaders->OptionalHeader.SizeOfCode;
					}
					else
						xez_xem = NULL;
				}
			}
		}

		return nBytes;
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_WideCharToMultiByte), WideCharToMultiByte__Hook);
}

VOID Detour__WriteFile()
{
	static decltype(&WriteFile) _WriteFile = WriteFile;

	decltype(&WriteFile) WriteFile__Hook = [](
		_In_ HANDLE hFile,
		_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
		_In_ DWORD nNumberOfBytesToWrite,
		_Out_opt_ LPDWORD lpNumberOfBytesWritten,
		_Inout_opt_ LPOVERLAPPED lpOverlapped) -> BOOL
	{
		buffer::request *request = (buffer::request*)lpBuffer;

		if (nNumberOfBytesToWrite == XIGNCODE_BUFSIZE &&
			request->size == XIGNCODE_BUFSIZE &&
			request->signature == XIGNCODE_SIGNATURE)
		{
			buffer::response *response = (buffer::response*)request->response;

			switch (request->operation)
			{
				case 0x0000030E: // start/stop 'watching'
				{
					// write response headers
					response->size = XIGNCODE_BUFSIZE;
					response->signature = 0x12121212;
					response->auth = ~request->key;
					response->status = STATUS_SUCCESS;

					if (lpNumberOfBytesWritten)
						*lpNumberOfBytesWritten = XIGNCODE_BUFSIZE;

					return TRUE;
				}
				case 0x00000311: // OpenProcess
				case 0x00000313: // ZwReadVirtualMemory or ZwWow64ReadVirtualMemory64
				case 0x00000314: // memcpy?
				case 0x00000315: // get driver name
				case 0x00000317: // ZwQueryInformationProcess
				case 0x00000318: // ZwWow64QueryInformationProcess64 or NtQueryInformationProcess (to get PEB or LDR)
				case 0x00000319: // some value from process
				case 0x0000031A: // QueryFullProcessImageNameW
				{
					return FALSE;
				}
				case 0x00000312: // some sort of value check used for 'MM.XMOD HkCorrupted'
				{
					static BOOL static_f = 1;
					// write response headers
					response->size = XIGNCODE_BUFSIZE;
					response->signature = 0x12121212;
					response->auth = ~request->key;
					response->status = STATUS_SUCCESS;
					response->params[0] = static_f;

					static_f = !static_f;

					if (lpNumberOfBytesWritten)
						*lpNumberOfBytesWritten = XIGNCODE_BUFSIZE;

					return TRUE;
				}
			}
		}

		return _WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_WriteFile), WriteFile__Hook);
}

VOID Detour__SetEnvironmentVariableW()
{
	static decltype(&SetEnvironmentVariableW) _SetEnvironmentVariableW = SetEnvironmentVariableW;

	decltype(&SetEnvironmentVariableW) SetEnvironmentVariableW__Hook = [](
		_In_ LPCWSTR lpName,
		_In_opt_ LPCWSTR lpValue) -> BOOL
	{
		if (wcsstr(lpName, L"TrayMsg") != NULL)
		{
			// XIGNCODE3 55854
			// CHECK VERSION HERE
			if (lpValue)
			{
				wprintf(L"%s\n", lpValue);

				if (wcsstr(lpValue, L"55854") == NULL)
				{
					printf("\tUpdate needed!\n");
				}
			}
		}

		return _SetEnvironmentVariableW(lpName, lpValue);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_SetEnvironmentVariableW), SetEnvironmentVariableW__Hook);
}

VOID WINAPI Hook(LPVOID *lplpDetectFunction)
{
	static std::list<LPVOID*> fList;

	LPVOID lpDetectFunction;

	EnterCriticalSection(&CriticalSection);

	if (std::find(fList.begin(), fList.end(), lplpDetectFunction) == fList.end())
	{
		// add to list
		fList.push_back(lplpDetectFunction);

		// function address
		lpDetectFunction = *lplpDetectFunction;

		if (xkaga_xem < lpDetectFunction && lpDetectFunction < (xkaga_xem + xkaga_size))
		{
			xkaga_operation(lplpDetectFunction);
		}

		if (xez_xem < lpDetectFunction && lpDetectFunction < (xez_xem + xez_size))
		{
			xez_operation(lplpDetectFunction);
		}
	}

	LeaveCriticalSection(&CriticalSection);
}

void __declspec(naked) HookWrapper__asm()
{
	__asm
	{
		pushad
		mov eax, [eax + 0x04]
		mov eax, [eax]
		push eax
		call Hook
		popad
		jmp dword ptr [lpHookAddress]
	}
}

VOID Detour__RtlEnterCriticalSection()
{
	static decltype(&EnterCriticalSection) _EnterCriticalSection = EnterCriticalSection;

	decltype(&EnterCriticalSection) EnterCriticalSection__Hook = [](_Inout_ LPCRITICAL_SECTION lpCriticalSection) -> VOID
	{
		static BOOL fDone = FALSE;

		DWORD *pdwReturnAddress;
		DWORD flOldProtect;
		MEMORY_BASIC_INFORMATION mbi;

		if (!fDone)
		{
			pdwReturnAddress = (DWORD*)_ReturnAddress();

			// xst.xem + 0x35C65 is function addr
			if (*pdwReturnAddress == 0x40246483)
			{
				lpHookAddress = reinterpret_cast<PBYTE>(pdwReturnAddress) + 0x7D;
				
				if (VirtualQuery(lpHookAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
				{
					printf("VirtualQuery failed %08X\n", GetLastError());
					goto label_end;
				}

				if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &flOldProtect))
				{
					printf("VirtualProtect failed %08X\n", GetLastError());
					goto label_end;
				}

				LPVOID lpvCopied = lpHookAddress;

				printf("\tDETECT HOOK %08X : %s\n", lpvCopied, DetourFunction(TRUE, &lpHookAddress, HookWrapper__asm) ? "SUCCESS" : "FAIL");

				if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, flOldProtect, &flOldProtect))
				{
					printf("VirtualProtect failed %08X\n", GetLastError());
					goto label_end;
				}

				// critical section
				InitializeCriticalSection(&CriticalSection);
				fDone = TRUE;
			}
		}

	label_end:
		return _EnterCriticalSection(lpCriticalSection);
	};

	DetourFunction(TRUE, reinterpret_cast<LPVOID*>(&_EnterCriticalSection), EnterCriticalSection__Hook);
}

VOID xigncode_bypass()
{
#ifdef DEBUG_MODE
	AllocConsole();
	AttachConsole(GetCurrentProcessId());
	FILE* pFile = nullptr;
	freopen_s(&pFile, "CON", "r", stdin);
	freopen_s(&pFile, "CON", "w", stdout);
	freopen_s(&pFile, "CON", "w", stderr);
#endif

	Detour__WideCharToMultiByte();				// Determine XignCode Module Address
	// Detour__GetVersion();						// Module Detection (not to call NtQueryVirtualMemory MemorySectionName)
	// Detour__SetEnvironmentVariableW();			// Version Check
	Detour__WriteFile();						// Driver Message
	Detour__CreateSemaphoreW();					// Multi Client
	Detour__NtOpenThread();						// Debugger
	// Detour__NtOpenProcess();					// Process Detection
	// Detour__NtQuerySystemInformation();			// Process Detection
	// Detour__NtQueryInformationProcess();		// Module Detection (PEB->LDR)
	// Detour__NtWow64QueryInformationProcess64();	// Module Detection (PEB->LDR)
	// Detour__GetWindowThreadProcessId();			// Window Detection

	Detour__RtlEnterCriticalSection();			// XignCode Detections
}