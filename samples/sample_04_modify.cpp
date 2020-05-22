#include "plh_Hook.h"
#include <stdio.h>

//..............................................................................

// target function

int foo(int a)
{
	printf("foo(%d)\n", a);
	return 123;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

// enter & leave hooks

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

#if (_PLH_CPU_AMD64)
#	if (_PLH_CPP_MSC)
	plh::RegArgBlock* regArgBlock = (plh::RegArgBlock*)(frameBase + plh::FrameOffset_RegArgBlock);
	int a = (int)regArgBlock->m_rcx;
	int newA = a * 2;
	regArgBlock->m_rcx = newA;
#	elif (_PLH_CPP_GCC)
	plh::RegArgBlock* regArgBlock = (plh::RegArgBlock*)(frameBase + plh::FrameOffset_RegArgBlock);
	int a = (int)regArgBlock->m_rdi;
	int newA = a * 2;
	regArgBlock->m_rdi = newA;
#	endif
#elif (_PLH_CPU_X86)
	plh::VaList va;
	plh::vaStart(va, frameBase);
	int* p = &plh::vaArg<int>(va);
	int a = *p;
	int newA = a * 2;
	*p = newA;
#endif

	printf("  modifying arg: (%d -> %d)\n", a, newA);
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

#if (_PLH_CPU_AMD64)
	int returnValue = (int)regRetBlock->m_rax;
	int newReturnValue = returnValue * 2;
	regRetBlock->m_rax = newReturnValue;
#elif (_PLH_CPU_X86)
	int returnValue = regRetBlock->m_eax;
	int newReturnValue = returnValue * 2;
	regRetBlock->m_eax = newReturnValue;
#endif

	printf(
		"  modifying retval: %d -> %d\n",
		returnValue,
		newReturnValue
		);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int
main()
{
	typedef int FooFunc(int);

	plh::HookArena arena;
	plh::Hook* fooHook = arena.allocate((void*)foo, (void*)0xabcdef, fooHookEnter, fooHookLeave);
	plh::enableHooks();
	int result = ((FooFunc*)fooHook)(10);
	printf("result: %d\n", result);
	return 0;
}

//..............................................................................
