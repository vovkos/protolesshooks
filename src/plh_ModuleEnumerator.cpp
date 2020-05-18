#include "plh_ModuleEnumerator.h"
#include <codecvt>
#include <psapi.h>
#include <assert.h>

namespace plh {

//..............................................................................

#if (_PLH_OS_WIN)

ModuleIterator::ModuleIterator(std::vector<HMODULE>&& moduleArray)
{
	m_moduleArray = moduleArray;
	m_index = 0;
}

ModuleIterator&
ModuleIterator::operator ++ ()
{
	if (m_index >= m_moduleArray.size())
		return *this;

	m_index++;
	m_moduleFileName.clear();
	return *this;
}

const std::string&
ModuleIterator::prepareModuleFileName() const
{
	assert(!m_moduleFileName.length());

	if (m_index >= m_moduleArray.size())
		return m_moduleFileName;

	enum
	{
		BuferLength = 1024,
	};

	wchar_t fileName[BuferLength];
	fileName[BuferLength - 1] = 0;
	::GetModuleFileNameW(m_moduleArray[m_index], fileName, BuferLength - 1);

	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> convert;
	m_moduleFileName = convert.to_bytes(fileName);
	return m_moduleFileName;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
enumerateModules(ModuleIterator* iterator)
{
	std::vector<HMODULE> moduleArray;

	for (;;)
	{
		size_t currentCount = moduleArray.size();
		DWORD requiredSize;

		::EnumProcessModules(
			::GetCurrentProcess(),
			moduleArray.data(),
			(DWORD)currentCount * sizeof(HMODULE),
			&requiredSize
			);

		size_t requiredCount = requiredSize / sizeof(HMODULE);
		if (requiredCount <= currentCount)
			break;

		moduleArray.resize(requiredCount);
	}

	*iterator = ModuleIterator(std::move(moduleArray));
	return true;
}

#elif (__linux__)

ModuleIterator&
ModuleIterator::operator ++ ()
{
	if (m_linkMap)
	{
		m_linkMap = m_linkMap->l_next;
		m_moduleFileName.clear();
	}

	return *this;
}

const sl::StringRef&
ModuleIterator::prepareModuleFileName() const
{
	if (!m_linkMap)
		return m_moduleFileName;

	m_moduleFileName = m_linkMap->l_name;

	if (m_moduleFileName.isEmpty())
		m_moduleFileName = io::getExeFilePath();

	return m_moduleFileName;
}

bool
enumerateModules(ModuleIterator* iterator)
{
	*iterator = ModuleIterator(_r_debug.r_map);
	return true;
}

#elif (__APPLE__)

ModuleIterator::ModuleIterator(size_t count)
{
	m_count = count;
	m_index = 0;
}

ModuleIterator&
ModuleIterator::operator ++ ()
{
	if (m_index >= m_count)
		return *this;

	m_index++;
	m_moduleFileName.clear();
	return *this;
}

void*
ModuleIterator::prepareModule() const
{
	ASSERT(!m_module.isOpen());

	if (m_index < m_count)
		m_module.open(getModuleFileName());

	return m_module;
}

const sl::StringRef&
ModuleIterator::prepareModuleFileName() const
{
	ASSERT(m_moduleFileName.isEmpty());

	if (m_index < m_count)
		m_moduleFileName = ::_dyld_get_image_name(m_index);

	return m_moduleFileName;
}

bool
enumerateModules(ModuleIterator* iterator)
{
	*iterator = ModuleIterator(_dyld_image_count());
	return true;
}

#endif

//..............................................................................

ModuleIterator
ModuleIterator::operator ++ (int)
{
	ModuleIterator it = *this;
	operator ++ ();
	return it;
}

//..............................................................................

} // namespace plh
