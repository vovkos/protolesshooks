#include "plh_Hook.h"
#include <stdio.h>

#undef NDEBUG
#include <assert.h>

#if (!_PLH_CPP_MSC || !_PLH_CPU_X86)
#	error invalid ABI for this program
#endif

//..............................................................................

class C
{
protected:
	int m_field;

public:
	C(int value = 0)
	{
		printf("C::C(this: %p)\n", this);
		m_field = value;
	}

	int
	__thiscall
	foo(int a)
	{
		printf("C::foo(this: %p, a: %d) { m_field: %d }\n", this, a, m_field);
		assert(a == 10);
		return m_field * a;
	}

	int
	__cdecl
	bar(int a)
	{
		printf("C::bar(this: %p, a: %d) { m_field: %d }\n", this, a, m_field);
		assert(a == 20);
		return m_field * a;
	}
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

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
	void* self = (void*)regArgBlock->m_ecx;

	plh::VaList va;
	plh::vaStart(va, frameBase);
	int a = plh::vaArg<int>(va);
	printf("  (this: %p, a: %d)\n", self, a);
	assert(a == 10);
	return plh::HookAction_Default;
}

plh::HookAction
barHookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"barHookEnter(func: %p, param: %p, frame: %p)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase
		);

	plh::VaList va;
	plh::vaStart(va, frameBase);
	void* self = plh::vaArg<void*>(va);
	int a = plh::vaArg<int>(va);
	printf("  (this: %p, a: %d)\n", self, a);
	assert(a == 20);
	return plh::HookAction_Default;
}

void
fooBarHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"fooBarHookLeave(func: %p, param: %p, frame: %p)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase
		);

	plh::RegRetBlock* regRetBlock = (plh::RegRetBlock*)(frameBase + plh::FrameOffset_RegRetBlock);
	int returnValue = regRetBlock->m_eax;
	printf("  -> %d\n", returnValue);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

template <
	typename To,
	typename From
	>
To
forceCast(From from)
{
	assert(sizeof(From) == sizeof(To));
	return *(To*)&from;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int main()
{
	typedef
	int
	(__thiscall C::*FooFunc)(int);

	typedef
	int
	(__cdecl C::*BarFunc)(int);

	plh::HookArena arena;

	plh::Hook* fooHook = arena.allocate(
		forceCast<void*>(&C::foo),
		(void*)0xabcdef,
		fooHookEnter,
		fooBarHookLeave
		);

	plh::Hook* barHook = arena.allocate(
		forceCast<void*>(&C::bar),
		(void*)0xabcdef,
		barHookEnter,
		fooBarHookLeave
		);

	C c(100);

	plh::enableHooks();

	int result = (c.*forceCast<FooFunc>(fooHook))(10);
	printf("result: %d\n", result);
	assert(result == 1000);

	result = (c.*forceCast<BarFunc>(barHook))(20);
	printf("result: %d\n", result);
	assert(result == 2000);
	return 0;
}

//..............................................................................
