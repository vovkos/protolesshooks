#include <stdio.h>
#include <stdint.h>
#include "protolesshooks.h"

//..............................................................................

// target function -- all register arguments are used up

int foo(int a, double b, int c, double d, int e, double f, int g, double h)
{
	printf("foo(%d, %f, %d, %f, %d, %f, %d, %f)\n", a, b, c, d, e, f, g, h);
	return 123;
}

//..............................................................................

void
fooHookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	printf(
		"fooHookEnter(targetFunc: %p, callbackParam: %p, frameBase: %p)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase
		);

	// register arguments start at frameBase - 16

	size_t regArgBase = frameBase - 16;

	// in case of foo, the mapping is as follows:

	//   a <-> rcx
	//   b <-> xmm1
	//   c <-> r8
	//   d <-> xmm2

	int a = *(const int*)(regArgBase - 8 * 0);
	double b = *(const double*)(regArgBase - 4 * 8 - 16 * 1);
	int c = *(const int*)(regArgBase - 8 * 2);
	double d = *(const double*)(regArgBase - 4 * 8 - 16 * 3);

	printf("  register args: (%d, %f, %d, %f)\n", a, b, c, d);

	// stack arguments start at frameBase + 16 + 8 * 4

	size_t stackArgBase = frameBase + 16 + 8 * 4;

	int e = *(const int*)(stackArgBase + 8 * 0);
	double f = *(const double*)(stackArgBase + 8 * 1);
	int g = *(const int*)(stackArgBase + 8 * 2);
	double h = *(const double*)(stackArgBase + 8 * 3);

	printf("  stack args: (%d, %f, %d, %f)\n", e, f, g, h);
}

void
fooHookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	size_t returnValue
	)
{
	printf(
		"fooHookLeave(targetFunc: %p, callbackParam: %p, frameBase: %p, returnValue: %zd/0x%zx)\n",
		targetFunc,
		callbackParam,
		(void*)frameBase,
		returnValue,
		returnValue
		);
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int main()
{
	typedef int FooFunc(int, double, int, double, int, double, int, double);

	plh::Hook* fooHook = plh::allocateHook(foo, (void*)0xabcdef, fooHookEnter, fooHookLeave, NULL);
	((FooFunc*)fooHook)(1, 10.1, 2, 20.2, 3, 30.3, 4, 40.4);
	plh::freeHook(fooHook);
	return 0;
}

//..............................................................................
