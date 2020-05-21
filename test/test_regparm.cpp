#include "plh_Hook.h"
#include <stdio.h>

#undef NDEBUG
#include <assert.h>

#if (!_PLH_CPP_GCC || !_PLH_CPU_X86)
#	error invalid ABI for this program
#endif

//..............................................................................

int
__attribute__((regparm(3)))
foo(
	int a, // eax
	int b, // edx
	int c, // ecx
	int d  // stack
	)
{
	printf("foo(%d, %d, %d, %d)\n", a, b, c, d);
	assert(a == 10 && b == 20 && c == 30 && d == 40);
	return a * 1000 + b * 100 + c * 10 + d;
}

plh::HookAction
fooHookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"fooHookEnter(func: %p, param: %p, frame: %p)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase
		);

	plh::RegArgBlock* regArgBlock = (plh::RegArgBlock*)(frameBase + plh::FrameOffset_RegArgBlock);
	int a = regArgBlock->m_eax;
	int b = regArgBlock->m_edx;
	int c = regArgBlock->m_ecx;

	plh::VaList va;
	plh::vaStart(va, frameBase);
	int d = plh::vaArg<int>(va);

	printf("  (%d, %d, %d, %d)\n", a, b, c, d);
	assert(a == 10 && b == 20 && c == 30 && d == 40);
	return plh::HookAction_Default;
}

void
fooHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"fooHookLeave(func: %p, param: %p, frame: %p)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase
		);

	plh::RegRetBlock* regRetBlock = (plh::RegRetBlock*)(frameBase + plh::FrameOffset_RegRetBlock);
	int returnValue = regRetBlock->m_eax;
	printf("  -> %d\n", returnValue);
	assert(returnValue == 12340);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int main()
{
	typedef
	int
	__attribute__((regparm(3)))
	FooFunc(int, int, int, int);

	plh::HookArena arena;

	plh::Hook* fooHook = arena.allocate(
		(void*)foo,
		(void*)0xabcdef,
		fooHookEnter,
		fooHookLeave
		);

	plh::enableHooks();
	int result = ((FooFunc*)fooHook)(10, 20, 30, 40);
	printf("result: %d\n", result);
	assert(result == 12340);
	return 0;
}

//..............................................................................
