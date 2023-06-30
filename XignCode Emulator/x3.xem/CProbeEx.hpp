#pragma once

#include "global.h"

#include "xclio.h"
#include "log.h"

struct CProbeEx
{
	typedef struct _PROBE_EX_CTX
	{
		void			*codebox;
		void			*request;
		uint			size;
		ProbeCallbackT	callback;
		void			*context;
	} PROBE_EX_CTX;

	HANDLE	m_hThread;
	DWORD	m_dwThreadId;

	HANDLE	m_hEvent;
	HANDLE	m_hEventRun;

	CRITICAL_SECTION			m_CriticalSection;	// CS for the list
	std::list<PROBE_EX_CTX>		m_lContext;
	// <- size 0x98

private:
	CProbeEx();
	~CProbeEx();

public:
	CProbeEx(const CProbeEx&) = delete;
	CProbeEx& operator=(const CProbeEx&) = delete;
	CProbeEx(CProbeEx&&) = delete;
	CProbeEx& operator=(CProbeEx&&) = delete;

private:
	static CProbeEx *m_pInstance;

public:
	static CProbeEx* GetInstance();
	static void Destroy();

public:
	uint	AddContext(void *codebox, const unsigned char *request, uint req_size, uint res_size, ProbeCallbackT callback, void *context);
	void	ProcessContext(PROBE_EX_CTX *ctx);
	BOOL	OnContextAdded();
	DWORD	ThreadTask();
};