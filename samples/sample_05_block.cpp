#include "plh_Hook.h"
#include <stdio.h>

//..............................................................................

// target function

int foo(int x)
{
	printf("foo(%d)\n", x);
	return 123;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

// enter hook

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
#	elif (_PLH_CPP_GCC)
	plh::RegArgBlock* regArgBlock = (plh::RegArgBlock*)(frameBase + plh::FrameOffset_RegArgBlock);
	int a = (int)regArgBlock->m_rdi;
#	endif
#elif (_PLH_CPU_X86)
	plh::VaList va;
	plh::vaStart(va, frameBase);
	int a = plh::vaArg<int>(va);
#endif

	plh::RegRetBlock* regRetBlock = (plh::RegRetBlock*)(frameBase + plh::FrameOffset_RegRetBlock);

	int returnValue;

	switch (a)
	{
	case 1:
		returnValue = foo(a);
		break;

	case 2:
		returnValue = 246;
		break;

	default:
		return plh::HookAction_JumpTarget; // in this case, it's the same as HookAction_Default
	}

#if (_PLH_CPU_AMD64)
	regRetBlock->m_rax = returnValue;
#elif (_PLH_CPU_X86)
	regRetBlock->m_eax = returnValue;
#endif

	return plh::HookAction_Return;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int
main()
{
	typedef int FooFunc(int);

	plh::HookArena arena;
	plh::Hook* fooHook = arena.allocate((void*)foo, (void*)0xabcdef, fooHookEnter, NULL);
	plh::enableHooks();

	printf("pass-through...\n");
	int result = ((FooFunc*)fooHook)(0);
	printf("result: %d\n", result);

	printf("proxy-call...\n");
	result = ((FooFunc*)fooHook)(1);
	printf("result: %d\n", result);

	printf("block completely...\n");
	result = ((FooFunc*)fooHook)(2);
	printf("result: %d\n", result);
	return 0;
}

//..............................................................................
