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

void seh_foo()
{
	printf("seh_foo\n");
	seh_bar();
}


int main()
{
	g_bazHook = plh::allocateHook(seh_baz, "BAZ!", onHookEnter, onHookLeave, onHookException);
	seh_foo();
	plh::freeHook(g_bazHook);
	return 0;
}

//..............................................................................
