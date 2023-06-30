#include "CProbeEx.hpp"

// singleton
CProbeEx *CProbeEx::m_pInstance = nullptr;

CProbeEx* CProbeEx::GetInstance()
{
	if (!m_pInstance)
		m_pInstance = new CProbeEx;

	return m_pInstance;
}

void CProbeEx::Destroy()
{
	if (m_pInstance)
	{
		delete m_pInstance;
		m_pInstance = nullptr;
	}
}

// sub_100021E0
DWORD WINAPI ThreadProc(__in LPVOID lpvParameter)
{
	return reinterpret_cast<CProbeEx*>(lpvParameter)->ThreadTask();
}

// sub_100292DE
CProbeEx::CProbeEx()
{
	m_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!m_hEvent)
		throw GetLastError();

	// suspended
	m_hThread = CreateThread(NULL, 0, ThreadProc, this, CREATE_SUSPENDED, &m_dwThreadId);
	if (m_hThread == NULL)
	{
		CloseHandle(m_hEvent);
		throw GetLastError();
	}

	InitializeCriticalSection(&m_CriticalSection);

	m_hEventRun = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!m_hEventRun)
		throw GetLastError();

	ResumeThread(m_hThread);
}

// sub_10029543
CProbeEx::~CProbeEx()
{
	Log("xclio:: probe term\n");

	if (m_hEvent != NULL)
	{
		CloseHandle(m_hEvent);
		m_hEvent = NULL;
	}

	if (m_hEventRun != NULL)
	{
		CloseHandle(m_hEventRun);
		m_hEventRun = NULL;
	}

	if (WaitForSingleObject(m_hThread, 10000) == WAIT_TIMEOUT)
		TerminateThread(m_hThread, 0);

	DeleteCriticalSection(&m_CriticalSection);
}

// sub_10029491
uint CProbeEx::AddContext(void *codebox, const unsigned char *request,
	uint req_size, uint res_size, ProbeCallbackT callback, void *context)
{
	PROBE_EX_CTX ctx;

	void *req_buffer = malloc(req_size);
	if (!req_buffer)
		return 0xE0010003;

	memcpy(req_buffer, request, req_size);

	ctx.codebox = codebox;
	ctx.request = req_buffer;
	ctx.size = res_size;
	ctx.callback = callback;
	ctx.context = context;

	// add to list
	EnterCriticalSection(&m_CriticalSection);
	m_lContext.push_back(ctx);	// copy members
	LeaveCriticalSection(&m_CriticalSection);

	// set event
	SetEvent(m_hEventRun);

	return 0;
}

// sub_10029A58
void CProbeEx::ProcessContext(PROBE_EX_CTX *ctx)
{
	void *response = malloc(ctx->size);
	if (!response) // error 0xE0010003
		return;

	if (Xclio_ProbeCodeBox(ctx->codebox, (const unsigned char *)ctx->request, response, ctx->size))
		if (m_lContext.size() == 0) // on probe completed
			ctx->callback(ctx->codebox, (const char *)ctx->request, (char *)response, ctx->size, ctx->context);
	else
	{
		uint error = GetLastError();

		if (error != 0xE0190305) // PROBE_EX_ERROR %08x
			Log("PROBE_EX_ERROR %08x\n", error);
	}

	free(response);
	free(ctx->request);
}

// sub_10029EDC
BOOL CProbeEx::OnContextAdded()
{
	PROBE_EX_CTX ctx;

	EnterCriticalSection(&m_CriticalSection);

	if (m_lContext.size() == 0)
	{
		LeaveCriticalSection(&m_CriticalSection);

		return FALSE;
	}

	ctx = m_lContext.back(); // memcpy
	m_lContext.pop_back();
	LeaveCriticalSection(&m_CriticalSection);

	this->ProcessContext(&ctx);

	return TRUE;
}

// sub_10029F4B
DWORD CProbeEx::ThreadTask()
{
	// sub_10029F4B
	HANDLE aHandle[2];
	DWORD dwResult;

	aHandle[0] = m_hEvent;
	aHandle[1] = m_hEventRun;

	Log("ProbeEx thread is running\n");

	while (TRUE)
	{
		dwResult = WaitForMultipleObjects(2, aHandle, 0, 1000);

		if (dwResult == WAIT_OBJECT_0)
			break;

		if (dwResult != WAIT_TIMEOUT)
		{
			while (this->OnContextAdded());
		}
	}

	Log("ProbeEx thread is about to end\n");

	return 0;
}