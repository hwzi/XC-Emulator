#include "global.h"

BOOL WINAPI DllMain(__in HINSTANCE hInstance, __in unsigned long fdwReason, __reserved void* lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		/*AllocConsole();
		SetConsoleTitle(L"Fuck, That's Delicious");
		AttachConsole(GetCurrentProcessId());

		FILE* pFile = nullptr;
		freopen_s(&pFile, "CON", "r", stdin);
		freopen_s(&pFile, "CON", "w", stdout);
		freopen_s(&pFile, "CON", "w", stderr);*/

		srand(GetTickCount());
		srand(rand());

		DisableThreadLibraryCalls(hInstance);
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
		FreeConsole();

	return TRUE;
}