#pragma once

#include "plh_HookCommon.h"
#include <map>
#include <vector>

namespace plh {

//..............................................................................

class ThreadState
{
protected:
	struct Ret
	{
		HookCommonContext* m_context;
		size_t m_originalRet;

		Ret()
		{
			m_context = NULL;
			m_originalRet = 0;
		}
	};

	struct Frame
	{
		Ret m_ret;
		std::vector<Ret> m_chainedRetStack; // forwarding via jmp
	};

protected:
	std::map<size_t, Frame> m_frameMap;

public:
	~ThreadState();

	void
	addFrame(
		HookCommonContext* context,
		size_t frameBase,
		size_t originalRet
		);

	size_t
	removeFrame(size_t frameBase);

	size_t
	getOriginalRet(size_t frameBase);

protected:
	std::map<size_t, Frame>::iterator
	findFrame(size_t frameBase);

	void
	cleanup(const std::map<size_t, Frame>::iterator& it);

	void
	restoreOriginalRets();
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
areHooksEnabled();

ThreadState*
getCurrentThreadState(bool createIfNotExists = true);

//..............................................................................

} // namespace plh
