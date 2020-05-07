#pragma once

#include <map>

namespace plh {

//..............................................................................

class HookMgr
{
protected:
	std::map<size_t, size_t> m_retMap;

public:
	void
	addFrame(
		size_t frameBase,
		size_t originalRet
		);

	size_t
	removeFrame(size_t frameBase);

	size_t
	findOriginalRet(size_t frameBase) const;

protected:
	void
	cleanup(const std::map<size_t, size_t>::iterator& it);
};

//..............................................................................

} // namespace plh
