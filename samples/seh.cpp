#if (WIN32)
#	include <windows.h>
#endif
#include <stdio.h>
#include "protolesshooks.h"

//..............................................................................

plh::Hook* g_bazHook;

void
onHookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf("onHookEnter(%p, %s, %llx)\n", targetFunc, (char*)callbackParam, frameBase);
}

void
onHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	size_t returnValue
	)
{
	printf("onHookLeave(%p, %s, %llx)\n", targetFunc, (char*)callbackParam, frameBase);
}

void
onHookException(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	EXCEPTION_RECORD* exception,
	CONTEXT* context
	)
{
	printf("onHookException(%p, %s, %llx)\n", targetFunc, (char*)callbackParam, frameBase);
}

//..............................................................................

int seh_baz_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_baz_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
}

int* g_p = NULL;

void seh_baz()
{
	__try
	{
		printf("seh_baz\n");
		*g_p = 0;
	}
	__except(seh_baz_filter(GetExceptionInformation()))
	{
		printf("seh_baz::__except\n");
	}
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int seh_bar_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_bar_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
}

void seh_bar()
{
	__try
	{
		printf("seh_bar\n");
		typedef void BazFunc();
		((BazFunc*)g_bazHook)();
	}
	__except(seh_bar_filter(GetExceptionInformation()))
	{
		printf("seh_bar::__except\n");
	}
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int seh_foo_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_foo_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
//	return EXCEPTION_EXECUTE_HANDLER;
}

void seh_foo()
{
	__try
	{
		printf("seh_foo\n");
		seh_bar();
	}
	__except(seh_foo_filter(GetExceptionInformation()))
	{
		printf("seh_foo::__except\n");
	}
}

//..............................................................................

int seh_main_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("seh_main_filter\n");

	DWORD oldProtect;
	::VirtualProtect(g_p, 4096, PAGE_READWRITE, &oldProtect);

	return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
#if (0)

#if (_AXL_OS_WIN)
	BOOL result = SymInitialize(INVALID_HANDLE_VALUE, NULL, true);

	__try
	{
#if (_PRINT_UNWIND_INFO)
		g_context.ContextFlags = CONTEXT_CONTROL;
		RtlCaptureContext(&g_context);
		printUnwindInfo(g_context.Rip);
#endif
		test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
	}
	__except(mainSehFilter(GetExceptionInformation()))
	{
		printf("exception caught in main()\n");
	}
#else
	setvbuf(stdout, NULL, _IOLBF, 1024);

	test(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
#endif

#endif

	g_p = (int*)::VirtualAlloc(
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READONLY
		);

	g_bazHook = plh::allocateHook(seh_baz, "BAZ!", onHookEnter, onHookLeave, onHookException);

	__try
	{
		printf("main\n");
		seh_foo();
	}
	__except(seh_main_filter(GetExceptionInformation()))
	{
		printf("main::__except\n");
	}

	plh::freeHook(g_bazHook);

	return 0;
}

//..............................................................................
