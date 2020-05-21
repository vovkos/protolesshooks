#include "plh_Hook.h"
#include <stdio.h>

#undef NDEBUG
#include <assert.h>

#if (!_PLH_CPP_MSC || !_PLH_CPU_X86)
#	error invalid ABI for this program
#endif

//..............................................................................

int
__fastcall
foo(
	int a, // ecx
	int b, // edx
	int c  // stack
	)
{
	printf("foo(%d, %d, %d)\n", a, b, c);
	assert(a == 10 && b == 20 && c == 30);
	return a * 100 + b * 10 + c;
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
	int a = regArgBlock->m_ecx;

	plh::VaList va;
	plh::vaStart(va, frameBase);
	int b = regArgBlock->m_edx;
	int c = plh::vaArg<int>(va);

	printf("  (%d, %d, %d)\n", a, b, c);
	assert(a == 10 && b == 20 && c == 30);
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
	assert(returnValue == 1230);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int main()
{
	typedef
	int
	__fastcall
	FooFunc(int, int, int);

	plh::HookArena arena;

	plh::Hook* fooHook = arena.allocate(
		(void*)foo,
		(void*)0xabcdef,
		fooHookEnter,
		fooHookLeave
		);

	plh::enableHooks();
	int result = ((FooFunc*)fooHook)(10, 20, 30);
	printf("result: %d\n", result);
	assert(result == 1230);
	return 0;
}

//..............................................................................
