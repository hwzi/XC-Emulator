#include "CXLock.hpp"

DWORD dwNumLock = 0;

CXLock::CXLock()
{
	InterlockedIncrement(&dwNumLock);
}

CXLock::~CXLock()
{
	InterlockedDecrement(&dwNumLock);
}

void CXLock::Empty()
{

}

BOOL sub_10026A66()
{
	return InterlockedCompareExchange(&dwNumLock, 0, 0) == 0;
}