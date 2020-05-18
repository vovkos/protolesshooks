#pragma once

#include "plh_Hook.h"

namespace plh {

//..............................................................................

struct HookCommonContext
{
	void* m_targetFunc;
	void* m_callbackParam;
	HookEnterFunc* m_enterFunc;
	HookLeaveFunc* m_leaveFunc;
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

HookAction
hookEnterCommon(
	HookCommonContext* context,
	size_t frameBase,
	size_t originalRet
	);

size_t
hookLeaveCommon(
	HookCommonContext* context,
	size_t frameBase
	);

//..............................................................................

} // namespace plh
