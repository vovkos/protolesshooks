#pragma once

#include <stdint.h>
#include <stdarg.h>

#if (_WIN32)
#	include <windows.h>
#endif

//..............................................................................

// detect ABI

#if (_MSC_VER)
#	define _PLH_CPP_MSC 1
#	if (defined _M_IX86)
#		define _PLH_CPU_X86 1
#	elif (defined _M_AMD64)
#		define _PLH_CPU_AMD64 1
#	elif (defined _M_ARM)
#		define _PLH_CPU_ARM32 1
#	elif (defined _M_ARM64)
#		define _PLH_CPU_ARM64 1
#	endif
#elif (__GNUC__)
#	define _PLH_CPP_GCC 1
#	if defined __i386__
#		define _PLH_CPU_X86 1
#	elif (defined __amd64__)
#		define _PLH_CPU_AMD64 1
#	elif (defined __arm__)
#		define _PLH_CPU_ARM32 1
#	elif (defined __aarch64__)
#		define _PLH_CPU_ARM64 1
#	endif
#endif

#if (!_PLH_CPU_X86 && !_PLH_CPU_AMD64)
#	error this ABI is not supported yet
#endif

namespace plh {

//..............................................................................

#if (_PLH_CPU_AMD64)
#	if (_PLH_CPP_MSC)

struct RegArgBlock
{
	uint64_t m_rcx;
	uint64_t m_rdx;
	uint64_t m_r8;
	uint64_t m_r9;
	double m_xmm0[2];
	double m_xmm1[2];
	double m_xmm2[2];
	double m_xmm3[2];
};

#	elif (_PLH_CPP_GCC)

struct RegArgBlock
{
	uint64_t m_rdi;
	uint64_t m_rsi;
	uint64_t m_rdx;
	uint64_t m_rcx;
	uint64_t m_r8;
	uint64_t m_r9;
	double m_xmm0[2];
	double m_xmm1[2];
	double m_xmm2[2];
	double m_xmm3[2];
	double m_xmm4[2];
	double m_xmm5[2];
	double m_xmm6[2];
	double m_xmm7[2];
};

#	endif
#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enum FrameOffset
{
#if (_PLH_CPU_X86)
	FrameOffset_StackArgBlock = 8,
#elif (_PLH_CPU_AMD64)
#	if (_PLH_CPP_MSC)
	FrameOffset_RegArgBlock   = -sizeof(RegArgBlock),
	FrameOffset_StackArgBlock = 16 + 8 * 4,
#	elif (_PLH_CPP_GCC)
	FrameOffset_RegArgBlock   = -sizeof(RegArgBlock),
	FrameOffset_StackArgBlock = 16,
#	endif
#endif
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct VaList
{
	char* m_p;
};

inline
void
vaStart(
	VaList& va,
	size_t frameBase
	)
{
	va.m_p = (char*)(frameBase + FrameOffset_StackArgBlock);
}

template<typename T>
T&
vaArg(VaList& va)
{
	T* p = (T*)va.m_p;
	va.m_p += (sizeof(T) + sizeof(intptr_t) - 1) & ~(sizeof(intptr_t) - 1);
	return *p;
}

inline
void
vaEnd(VaList& va)
{
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

typedef
void
HookEnterFunc(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	);

typedef
void
HookLeaveFunc(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	size_t returnValue
	);

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct Hook;

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc
	);

void
freeHook(Hook* hook);

//..............................................................................

} // namespace plh {
