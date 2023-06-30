#pragma once

#ifndef _CRT_SECURE_NO_WARNINGS
	#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _STL_SECURE_NO_WARNINGS
	#define _STL_SECURE_NO_WARNINGS
#endif

#ifndef WIN32_LEAN_AND_MEAN
	#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <list>
#include <map>

#include <WinInet.h>
#pragma comment(lib, "WinInet.lib")

#include "defs.h"
#include "structs.h"