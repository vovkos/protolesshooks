#pragma once

#if (WIN32)
#	include <windows.h>
#endif

namespace plh {

//..............................................................................

enum FrameOffset
{
	FrameOffset_RegArg   = -16,

#if (WIN32)
	FrameOffset_StackArg = 16 + 8 * 4,
#else
	FrameOffset_StackArg = 16,
#endif
};

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

#if (WIN32)

typedef
void
HookExceptionFunc(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase,
	EXCEPTION_RECORD* exception,
	CONTEXT* context
	);

#else

typedef
void
HookExceptionFunc(); // unused on POSIX

#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct Hook;

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc,
	HookExceptionFunc* exceptionFunc
	);

void
freeHook(Hook* hook);

//..............................................................................

} // namespace plh {
