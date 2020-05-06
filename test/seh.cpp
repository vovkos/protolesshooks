#if (_WIN32)
#	include <windows.h>
#endif
#include <stdio.h>
#include "protolesshooks.h"

//..............................................................................

plh::Hook* g_bazHook;

void
bazHookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf("bazHookEnter(%p, '%s', %zx)\n", targetFunc, (char*)callbackParam, frameBase);
}

void
bazHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	size_t returnValue
	)
{
	printf("bazHookLeave(%p, '%s', %zx)\n", targetFunc, (char*)callbackParam, frameBase);
}

//..............................................................................

int
baz_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("baz_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
}

int* g_p = NULL;

void
baz()
{
	__try
	{
		printf("baz\n");
		*g_p = 0;
	}
	__except(baz_filter(GetExceptionInformation()))
	{
		printf("baz:__except\n");
	}
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int
bar_filter(EXCEPTION_POINTERS* exceptionPointers)
{
	printf("bar_filter\n");
	return EXCEPTION_CONTINUE_SEARCH;
}

void
bar()
{
	__try
	{
		printf("bar\n");
		typedef void BazFunc();
		((BazFunc*)g_bazHook)();
	}
	__except(bar_filter(GetExceptionInformation()))
	{
		printf("bar:__except\n");
	}
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int
foo_filter(
	EXCEPTION_POINTERS* exceptionPointers,
	bool recover
	)
{
	printf("foo_filter\n");

	if (!recover)
		return EXCEPTION_EXECUTE_HANDLER;

	DWORD oldProtect;
	::VirtualProtect(g_p, 4096, PAGE_READWRITE, &oldProtect);
	return EXCEPTION_CONTINUE_EXECUTION;
}

void
foo(bool recover)
{
	__try
	{
		printf("foo\n");
		bar();
	}
	__except(foo_filter(GetExceptionInformation(), recover))
	{
		printf("foo:__except\n");
	}
}

//..............................................................................

int
main()
{
	g_p = (int*)::VirtualAlloc(
		NULL,
		4096,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READONLY
		);

	g_bazHook = plh::allocateHook(baz, "hook-param", bazHookEnter, bazHookLeave);

	foo(false);
	foo(true);

	plh::freeHook(g_bazHook);

	return 0;
}

//..............................................................................
