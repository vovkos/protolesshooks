#pragma once

#include "plh_Def.h"

#if (_PLH_OS_WIN)
#	include <windows.h>
#elif (_PLH_OS_DARWIN)
#	include "plh_DynamicLib.h"
#endif
#include <vector>

namespace plh {

//..............................................................................

#if (_WIN32)

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

	const std::string&
	getModuleFileName() const
	{
		return !m_moduleFileName.empty() ? m_moduleFileName : prepareModuleFileName();
	}

protected:
	const std::string&
	prepareModuleFileName() const;
};

#elif (__linux__)

class ModuleIterator
{
protected:
	mutable sl::StringRef m_moduleFileName;
	struct link_map* m_linkMap;

public:
	ModuleIterator()
	{
		m_linkMap = NULL;
	}

	ModuleIterator(struct link_map* linkMap)
	{
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

	const sl::StringRef&
	getModuleFileName() const
	{
		return !m_moduleFileName.isEmpty() ? m_moduleFileName : prepareModuleFileName();
	}

protected:
	const sl::StringRef&
	prepareModuleFileName() const;
};

#elif (_AXL_OS_DARWIN)

class ModuleIterator
{
protected:
	mutable DynamicLib m_module;
	mutable sl::StringRef m_moduleFileName;
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

	const sl::StringRef&
	getModuleFileName() const
	{
		return !m_moduleFileName.isEmpty() ? m_moduleFileName : prepareModuleFileName();
	}

	size_t
	getImageIndex() const
	{
		return m_index;
	}

protected:
	void*
	prepareModule() const;

	const sl::StringRef&
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
