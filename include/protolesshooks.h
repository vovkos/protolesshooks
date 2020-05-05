#pragma once

#if (WIN32)
#	include <windows.h>
#endif

namespace plh {

struct Hook;

//..............................................................................

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

#endif

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

#if (WIN32)

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc,
	HookExceptionFunc* exceptionFunc
	);

#else

Hook*
allocateHook(
	void* targetFunc,
	void* callbackParam,
	HookEnterFunc* enterFunc,
	HookLeaveFunc* leaveFunc
	);

#endif

void
freeHook(Hook* hook);

//..............................................................................

} // namespace plh {
