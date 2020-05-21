#pragma once

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

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

// detect OS

#ifdef _WIN32
#	define _PLH_OS_WIN 1
#elif (defined __linux__)
#	define _PLH_OS_LINUX 1
#elif (defined __APPLE__)
#	define _PLH_OS_DARWIN 1
#else
#	error this OS is not supported yet
#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

// compiler-agnostic defs for cdecl & stdcall

#if (_PLH_CPP_MSC)
#	define PLH_CDECL   __cdecl
#	define PLH_STDCALL __stdcall
#elif (_PLH_CPP_GCC)
#	if (_PLH_CPU_X86)
#		define PLH_CDECL   __attribute__((cdecl))
#		define PLH_STDCALL __attribute__((stdcall))
#	else
#		define PLH_CDECL
#		define PLH_STDCALL
#	endif
#endif

//..............................................................................

#include <stddef.h>
#include <stdint.h>
