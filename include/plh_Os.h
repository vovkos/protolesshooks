#pragma once

#include "plh_Def.h"
#include <assert.h>

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

// dlopen/dlcose wrapper

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

	operator void* ()
	{
		return m_module;
	}

	bool
	isOpen()
	{
		return m_module != NULL;
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
	void* p,
	size_t size
	)
{
	assert(p && "executable pages are not allocated");
	return ::VirtualFree(p, size, MEM_RELEASE) != 0;
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
	assert(p && "executable pages are not allocated");
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
	assert(slot != -1 && "TLS slot is not allocated");
	return (intptr_t)::TlsGetValue((DWORD)slot);
}

inline
bool
setTlsValue(
	size_t slot,
	intptr_t value
	)
{
	assert(slot != -1 && "TLS slot is not allocated");
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

// static inline helps avoiding weak-linkage by clang on macOS;
// these two functions should never be hooked in the usual way!

static
inline
intptr_t
getTlsValue(size_t slot)
{
	assert(slot != -1 && "TLS slot is not allocated");
	return (intptr_t)::pthread_getspecific((pthread_key_t)slot);
}

static
inline
bool
setTlsValue(
	size_t slot,
	intptr_t value
	)
{
	assert(slot != -1 && "TLS slot is not allocated");
	return ::pthread_setspecific((pthread_key_t)slot, (void*)value) == 0;
}

#endif

//..............................................................................

// OS-agnostic TID query

inline
uint64_t
getCurrentThreadId()
{
#if (_PLH_OS_WIN)
	return ::GetCurrentThreadId();
#else
	return (uint64_t)::pthread_self();
#endif
}

//..............................................................................

} // namespace plh
