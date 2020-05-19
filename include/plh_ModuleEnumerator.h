#pragma once

#include "plh_Os.h"
#include <vector>

#if (_PLH_OS_WIN)
#	include <windows.h>
#elif (_PLH_OS_LINUX)
#	include <link.h>
#endif

namespace plh {

//..............................................................................

#if (_PLH_OS_WIN)

class ModuleIterator
{
protected:
	mutable std::string m_moduleFileName;
	std::vector<HMODULE> m_moduleArray;
	size_t m_index;

public:
    ModuleIterator()
	{
		m_index = -1;
	}

	ModuleIterator(std::vector<HMODULE>&& moduleArray);

	operator bool () const
	{
		return m_index < m_moduleArray.size();
	}

    ModuleIterator&
    operator ++ ();

	ModuleIterator
	operator ++ (int);

	void*
	getModule() const
	{
		return m_index < m_moduleArray.size() ? m_moduleArray[m_index] : NULL;
	}

	const char*
	getModuleFileName() const
	{
		return !m_moduleFileName.empty() ? m_moduleFileName.c_str() : prepareModuleFileName();
	}

protected:
	const char*
	prepareModuleFileName() const;
};

#elif (_PLH_OS_LINUX)

class ModuleIterator
{
protected:
	mutable const char* m_moduleFileName;
	link_map* m_linkMap;

public:
	ModuleIterator()
	{
		m_moduleFileName = NULL;
		m_linkMap = NULL;
	}

	ModuleIterator(link_map* linkMap)
	{
		m_moduleFileName = NULL;
		m_linkMap = linkMap;
	}

	operator bool () const
	{
		return m_linkMap != NULL;
	}

	ModuleIterator&
	operator ++ ();

	ModuleIterator
	operator ++ (int);

	void*
	getModule() const
	{
		return m_linkMap;
	}

	const char*
	getModuleFileName() const
	{
		return m_moduleFileName ? m_moduleFileName : prepareModuleFileName();
	}

protected:
	const char*
	prepareModuleFileName() const;
};

#elif (_PLH_OS_DARWIN)

class ModuleIterator
{
protected:
	mutable DynamicLib m_module;
	mutable const char* m_moduleFileName;
	size_t m_count;
	size_t m_index;

public:
	ModuleIterator(size_t count = 0);

	operator bool ()
	{
		return m_index < m_count;
	}

	ModuleIterator&
	operator ++ ();

	ModuleIterator
	operator ++ (int);

	void*
	getModule() const
	{
		return m_module.isOpen() ? (void*)m_module : prepareModule();
	}

	const char*
	getModuleFileName() const
	{
		return m_moduleFileName ? m_moduleFileName : prepareModuleFileName();
	}

	size_t
	getImageIndex() const
	{
		return m_index;
	}

protected:
	void*
	prepareModule() const;

	const char*
	prepareModuleFileName() const;
};

#endif

bool
enumerateModules(ModuleIterator* iterator);

inline
ModuleIterator
enumerateModules()
{
	ModuleIterator iterator;
	enumerateModules(&iterator);
	return iterator;
}

//..............................................................................

} // namespace plh
