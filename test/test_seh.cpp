#include "plh_Hook.h"
#include <stdio.h>

#if (_WIN32)
#	include <windows.h>
#endif

//..............................................................................

plh::Hook* g_bazHook;

plh::HookAction
bazHookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"bazHookEnter(func: %p, param: %s, frame: %p)\n",
		targetFunc,
		(char*)callbackParam,
		(void*)frameBase
		);

	return plh::HookAction_Default;
}

void
bazHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"bazHookLeave(func: %p, param: %s, frame: %p)\n",
		targetFunc,
		(char*)callbackParam,
		(void*)frameBase
		);
}

#if (_PLH_CPU_AMD64)

void
bazHookException(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	EXCEPTION_RECORD* exception,
	CONTEXT* context
	)
{
	printf(
		"bazHookException(func: %p, param: %s, frame: %p, error: %x, addr: %p)\n",
		targetFunc,
		(char*)callbackParam,
		(void*)frameBase,
		exception->ExceptionCode,
		exception->ExceptionAddress
		);
}

#endif

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

	plh::HookArena arena;
	g_bazHook = arena.allocate(baz, "hook-param", bazHookEnter, bazHookLeave);

#if (_PLH_CPU_AMD64)
	plh::setHookExceptionFunc(g_bazHook, bazHookException);
#endif

	plh::enableHooks();

	printf("without recovery...\n");
	foo(false);

	printf("\nnow with recovery...\n");
	foo(true);

	return 0;
}

//..............................................................................
