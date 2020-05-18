#pragma once

#include "plh_Def.h"
#include <stddef.h>
#include <stdint.h>

#if (_PLH_OS_WIN)
#	include <windows.h>
#else
#	include <unistd.h>
#	include <dlfcn.h>
#	include <pthread.h>
#	include <sys/mman.h>
#endif


namespace plh {

//..............................................................................

// dlopen/dlcose wraper

#if (!_PLH_OS_WIN)

class DynamicLib
{
protected:
	void* m_module;

public:
	DynamicLib()
	{
		m_module = NULL;
	}

	~DynamicLib()
	{
		close();
	}

	bool
	open(
		const char* fileName,
		int flags
		);

	void
	close();
};

#endif

//..............................................................................

// OS-agnostic page size detection

inline
size_t
getPageSize()
{
	static size_t pageSize = 0;
	if (pageSize)
		return pageSize;

#if (_PLH_OS_WIN)
	SYSTEM_INFO systemInfo;
	::GetSystemInfo(&systemInfo);
	pageSize = systemInfo.dwPageSize;
#else
	pageSize = ::sysconf(_SC_PAGE_SIZE);
#endif

	return pageSize;
}

//..............................................................................

// OS-agnostic executable page allocation

#if (_PLH_OS_WIN)

inline
void*
allocateExecutablePages(size_t size)
{
	return ::VirtualAlloc(
		NULL,
		size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
		);
}

inline
bool
freeExecutablePages(
	void* pages,
	size_t size
	)
{
	return ::VirtualFree(pages, size, MEM_RELEASE) != 0;
}

#else

inline
void*
allocateExecutablePages(size_t size)
{
	return ::mmap(
		NULL,
		size,
		PROT_EXEC | PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0
		);
}

inline
bool
freeExecutablePages(
	void* p,
	size_t size
	)
{
	return ::munmap(p, size) == 0;
}

#endif

//..............................................................................

// OS-agnostic TLS management

#if (_PLH_OS_WIN)

inline
size_t
createTlsSlot()
{
	return (int32_t)::TlsAlloc();
}

inline
intptr_t
getTlsValue(size_t slot)
{
	return (intptr_t)::TlsGetValue((DWORD)slot);
}

inline
bool
setTlsValue(
	size_t slot,
	intptr_t value
	)
{
	return ::TlsSetValue((DWORD)slot, (void*)value) != 0;
}

#else

typedef
void
TlsDestructFunc(void* p);

size_t
createDestructibleTlsSlot(TlsDestructFunc* destructFunc);

inline
size_t
createTlsSlot()
{
	return createDestructibleTlsSlot(NULL);
}

inline
intptr_t
getTlsValue(size_t slot)
{
	return (intptr_t)::pthread_getspecific((pthread_key_t)slot);
}

inline
bool
setTlsValue(
	size_t slot,
	intptr_t value
	)
{
	return ::pthread_setspecific((pthread_key_t)slot, (void*)value) == 0;
}

#endif

//..............................................................................

} // namespace plh
