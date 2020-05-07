#include <assert.h>

#include "plh_HookMgr.h"

namespace plh {

//..............................................................................

void
HookMgr::addFrame(
	size_t frameBase,
	size_t originalRet
	)
{
	std::pair<std::map<size_t, size_t>::iterator, bool> result = m_frameMap.insert(std::pair<size_t, size_t>(frameBase, originalRet));
	cleanup(result.first);
}

size_t
HookMgr::removeFrame(size_t frameBase)
{
	std::map<size_t, size_t>::iterator it = m_frameMap.find(frameBase);
	if (it == m_frameMap.end())
	{
		assert(false && "protolesshooks: FATAL ERROR: return address not found");
		return 0;
	}

	size_t originalRet = it->second;

	cleanup(it);
	m_frameMap.erase(it);
	return originalRet;
}

size_t
HookMgr::findOriginalRet(size_t frameBase) const
{
	std::map<size_t, size_t>::const_iterator it = m_frameMap.find(frameBase);
	if (it == m_frameMap.end())
	{
		assert(false && "protolesshooks: FATAL ERROR: return address not found");
		return 0;
	}

	return it->second;
}

void
HookMgr::cleanup(const std::map<size_t, size_t>::iterator& it)
{
	// we may end up with abandoned frames (e.g., due to SEH or longjmp-s)
	// this loop cleans up all frames *above* the current one

	while (it != m_frameMap.begin())
		m_frameMap.erase(std::prev(it));
}

//..............................................................................

} // namespace plh
