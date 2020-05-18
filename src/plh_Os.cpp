#include "plh_Os.h"

namespace plh {

#if (!_PLH_OS_WIN)

//..............................................................................

bool
DynamicLib::open(
	const char* fileName,
	int flags
	)
{
	close();
	m_module = ::dlopen(fileName, flags);
	return m_module != NULL;
}

void
DynamicLib::close()
{
	if (m_module)
	{
		::dlclose(m_module);
		m_module = NULL;
	}
}

//..............................................................................

inline
size_t
createDestructibleTlsSlot(TlsDestructFunc* destructFunc)
{
	pthread_key_y key;
	int result = ::pthread_key_create(&key, destrcutFunc);
	return result == 0 ? (size_t)key : -1;
}

//..............................................................................

#endif

} // namespace plh
