#include "plh_Hook.h"
#include <stdio.h>

#undef NDEBUG
#include <assert.h>

#if (!_PLH_CPU_X86)
#	error invalid ABI for this program
#endif

//..............................................................................

int
PLH_STDCALL
foo(int a) // one argument is all it takes for ret <n> to mess up the stack
{
	printf("foo(%d)\n", a);
	return 10;
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

	plh::VaList va;
	plh::vaStart(va, frameBase);
	int a = plh::vaArg<int>(va);
	printf("  (%d)\n", a);
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
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int main()
{
	typedef
	int
	PLH_STDCALL
	FooFunc(int);

	plh::HookArena arena;

	plh::Hook* fooHook = arena.allocate(
		(void*)foo,
		(void*)0xabcdef,
		fooHookEnter,
		fooHookLeave
		);

	plh::enableHooks();
	((FooFunc*)fooHook)(10);
	return 0;
}

//..............................................................................
