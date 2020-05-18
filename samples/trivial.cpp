#include <stdio.h>
#include "plh_Hook.h"

//..............................................................................

// target function

void foo()
{
	printf("foo\n");
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

	return plh::HookAction_Default;
}

void
fooHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	plh::RegRetBlock* regRetBlock = (plh::RegRetBlock*)(frameBase + plh::FrameOffset_RegRetBlock);

	printf(
		"fooHookLeave(func: %p, param: %p, frame: %p)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase
		);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int
main()
{
	typedef int FooFunc();

	plh::HookArena arena;
	plh::Hook* fooHook = arena.allocate((void*)foo, (void*)0xabcdef, fooHookEnter, fooHookLeave);
	plh::enableHooks();
	((FooFunc*)fooHook)();
	return 0;
}

//..............................................................................
