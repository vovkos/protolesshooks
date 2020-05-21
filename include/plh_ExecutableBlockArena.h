#pragma once

#include "plh_Os.h"
#include <vector>

namespace plh {

//..............................................................................

template <typename T>
class ExecutableBlockArena
{
protected:
	size_t m_allocSize;
	std::vector<void*> m_pageArray;
	char* m_current;
	char* m_end;

public:
	ExecutableBlockArena(size_t allocMultiplier = 1)
	{
		size_t pageSize = getPageSize();
		m_allocSize = ((sizeof(T) + pageSize - 1) & ~(pageSize - 1)) * allocMultiplier;
		m_current = NULL;
		m_end = NULL;
	}

	~ExecutableBlockArena()
	{
		free();
	}

	T*
	allocate()
	{
		if (m_end - m_current >= sizeof(T))
		{
			T* p = (T*)m_current;
			m_current += sizeof(T);
			return p;
		}

		void* page = allocateExecutablePages(m_allocSize);
		if (!page)
			return NULL;

		m_pageArray.push_back(page);
		m_current = (char*)page + sizeof(T);
		m_end = (char*)page + m_allocSize;
		return (T*)page;
	}

	void
	free()
	{
		size_t count = m_pageArray.size();
		for (size_t i = 0; i < count; i++)
			freeExecutablePages(m_pageArray[i], m_allocSize);

		m_pageArray.clear();
		m_current = NULL;
		m_end = NULL;
	}

	void
	detach()
	{
		m_pageArray.clear();
		m_current = NULL;
		m_end = NULL;
	}
};

//..............................................................................

} // namespace plh
