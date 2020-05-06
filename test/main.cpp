#include <stdio.h>
#include <stdint.h>
#include "protolesshooks.h"

//..............................................................................

// target function -- all register arguments are used up

int foo(
	int a, double b,
	int c, double d,
	int e, double f,  // on microsoft x64, e passed on stack
	int g, double h,
	int i, double j,
	int k, double l,
	int m, double n,  // on systemv amd64, m passed on stack
	int o, double p,
	int q, double r   // on systemv amd64, r passed on stack
	)
{
	printf(
		"foo("
		"%d, %f, %d, %f, %d, %f, "
		"%d, %f, %d, %f, %d, %f, "
		"%d, %f, %d, %f, %d, %f)\n",
		a, b, c, d, e, f,
		g, h, i, j, k, l,
		m, n, o, p, q, r
		);

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

	size_t stackArgBase = frameBase + plh::FrameOffset_StackArgBlock;

#if (_PLH_CPU_AMD64)
#	if (_PLH_CPP_MSC)

	plh::RegArgBlock* regArgBlock = (plh::RegArgBlock*)(frameBase + plh::FrameOffset_RegArgBlock);

	int a = (int)regArgBlock->m_rcx;
	double b = regArgBlock->m_xmm1[1];
	int c = (int)regArgBlock->m_r8;
	double d = regArgBlock->m_xmm1[3];

	int e = *(int*)(stackArgBase + 8 * 0);
	double f = *(double*)(stackArgBase + 8 * 1);
	int g = *(int*)(stackArgBase + 8 * 2);
	double h = *(double*)(stackArgBase + 8 * 3);
	int i = *(int*)(stackArgBase + 8 * 4);
	double j = *(double*)(stackArgBase + 8 * 5);
	int k = *(int*)(stackArgBase + 8 * 6);
	double l = *(double*)(stackArgBase + 8 * 7);
	int m = *(int*)(stackArgBase + 8 * 8);
	double n = *(double*)(stackArgBase + 8 * 9);
	int o = *(int*)(stackArgBase + 8 * 10);
	double p = *(double*)(stackArgBase + 8 * 11);
	int q = *(int*)(stackArgBase + 8 * 12);
	double r = *(double*)(stackArgBase + 8 * 13);

	printf(
		"  ("
		"%d, %f, %d, %f, %d, %f, "
		"%d, %f, %d, %f, %d, %f, "
		"%d, %f, %d, %f, %d, %f)\n",
		a, b, c, d, e, f,
		g, h, i, j, k, l,
		m, n, o, p, q, r
		);
#	elif (_PLH_CPP_GCC)
	plh::RegArgBlock* regArgBlock = (plh::RegArgBlock*)(frameBase + plh::FrameOffset_RegArgBlock);

	int a = (int)regArgBlock->m_rdi;
	int c = (int)regArgBlock->m_rsi;
	int e = (int)regArgBlock->m_rdx;
	int g = (int)regArgBlock->m_rcx;
	int i = (int)regArgBlock->m_r8;
	int k = (int)regArgBlock->m_r9;
	double b = regArgBlock->m_xmm0[0];
	double d = regArgBlock->m_xmm1[0];
	double f = regArgBlock->m_xmm2[0];
	double h = regArgBlock->m_xmm3[0];
	double j = regArgBlock->m_xmm4[0];
	double l = regArgBlock->m_xmm5[0];
	double n = regArgBlock->m_xmm6[0];
	double p = regArgBlock->m_xmm7[0];

	int m = *(int*)(stackArgBase + 8 * 0);
	int o = *(int*)(stackArgBase + 8 * 1);
	int q = *(int*)(stackArgBase + 8 * 2);
	double r = *(double*)(stackArgBase + 8 * 3);

	printf(
		"  ("
		"%d, %f, %d, %f, %d, %f, "
		"%d, %f, %d, %f, %d, %f, "
		"%d, %f, %d, %f, %d, %f)\n",
		a, b, c, d, e, f,
		g, h, i, j, k, l,
		m, n, o, p, q, r
		);

#	endif
#endif
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

int
main()
{
	typedef int FooFunc(
		int, double,
		int, double,
		int, double,
		int, double,
		int, double,
		int, double,
		int, double,
		int, double,
		int, double
		);

	plh::Hook* fooHook = plh::allocateHook((void*)foo, (void*)0xabcdef, fooHookEnter, fooHookLeave, NULL);

	((FooFunc*)fooHook)(
		1, 10.1,
		2, 20.2,
		3, 30.3,
		4, 40.4,
		5, 50.5,
		6, 60.6,
		7, 70.7,
		8, 80.8,
		9, 90.9
		);

	plh::freeHook(fooHook);
	return 0;
}

//..............................................................................
