#include "plh_ImportWriteProtection.h"
#include "plh_ModuleEnumerator.h"
#include "plh_Os.h"

#if (_PLH_OS_LINUX)
#	include <link.h>
#	if (_PLH_CPU_AMD64 || _PLH_CPU_X86)
#		define DT_THISPROCNUM 0
#	endif

// we use undocumented fields in the link map; it's a bit hackish, but
// there's no clean way of mapping module handle to Elf headers anyway

struct link_map_full: link_map
{
	link_map* l_real;
	Lmid_t l_ns;
	struct libname_list* l_libname;

	ElfW(Dyn)* l_info[
		DT_NUM +
		DT_THISPROCNUM +
		DT_VERSIONTAGNUM +
		DT_EXTRANUM +
		DT_VALNUM +
		DT_ADDRNUM
		];

	const ElfW(Phdr)* l_phdr;
	ElfW(Addr) l_entry;
	ElfW(Half) l_phnum;
	ElfW(Half) l_ldnum;
};
#endif

namespace plh {

//..............................................................................

#if (_PLH_OS_WIN)

IMAGE_NT_HEADERS*
getPeHdr(HMODULE hModule);

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
disableImportWriteProtection(
	void* module,
	ImportWriteProtectionBackup* backup
	)
{
	if (!module)
		module = ::GetModuleHandle(NULL);

	IMAGE_NT_HEADERS* peHdr = getPeHdr((HMODULE)module);
	if (!peHdr)
		return false;

	IMAGE_DATA_DIRECTORY* iatDir = (IMAGE_DATA_DIRECTORY*)&peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	size_t begin = (size_t)module + iatDir->VirtualAddress;
	size_t end = begin + iatDir->Size;
	size_t pageSize = getPageSize();

	begin &= ~(pageSize - 1);
	end = (end + pageSize - 1) & ~(pageSize - 1);

	backup->m_p = (char*)begin;
	backup->m_size = end - begin;

	return ::VirtualProtect(
		backup->m_p,
		backup->m_size,
		PAGE_EXECUTE_READWRITE,
		(DWORD*)&backup->m_oldProtection
		) != 0;
}

bool
disableImportWriteProtection(
	const ModuleIterator& moduleIterator,
	ImportWriteProtectionBackup* backup
	)
{
	return disableImportWriteProtection(moduleIterator.getModule(), backup);
}

bool
restoreImportWriteProtection(const ImportWriteProtectionBackup* backup)
{
	DWORD oldProtect;

	return ::VirtualProtect(
		backup->m_p,
		backup->m_size,
		backup->m_oldProtection,
		&oldProtect
		) != 0;
}

#elif (_PLH_OS_LINUX)

bool
disableImportWriteProtection(
	void* module,
	ImportWriteProtectionBackup* backup
	)
{
	link_map_full* linkMap = (link_map_full*)module;
	for (size_t i = 0; i < linkMap->l_phnum; i++)
	{
		const ElfW(Phdr)* phdr = &linkMap->l_phdr[i];
		if (phdr->p_type != PT_GNU_RELRO) // read-only-after-relocation (contains GOT)
			continue;

		size_t begin = linkMap->l_addr + phdr->p_vaddr;
		size_t end = begin + phdr->p_memsz;

		size_t pageSize = getPageSize();
		begin &= ~(pageSize - 1);
		end = (end + pageSize - 1) & ~(pageSize - 1);

		backup->m_p = (char*)begin;
		backup->m_size = end - begin;
		backup->m_flags = phdr->p_flags;

		int result = ::mprotect(backup->m_p, backup->m_size, PROT_READ | PROT_WRITE | PROT_EXEC);
		return result != -1;
	}

	// GOT not found, still OK

	backup->m_p = NULL;
	backup->m_size = 0;
	backup->m_flags = 0;
	return true;
}

bool
disableImportWriteProtection(
	const ModuleIterator& moduleIterator,
	ImportWriteProtectionBackup* backup
	)
{
	return disableImportWriteProtection(moduleIterator.getModule(), backup);
}

bool
restoreImportWriteProtection(const ImportWriteProtectionBackup* backup)
{
	if (!backup->m_p) // nothing to restore
		return true;

	int prot = 0;

	if (backup->m_flags & PF_R)
		prot |= PROT_READ;

	if (backup->m_flags & PF_W)
		prot |= PROT_WRITE;

	if (backup->m_flags & PF_X)
		prot |= PROT_EXEC;

	int result = ::mprotect(backup->m_p, backup->m_size, prot);
	return result != -1;
}

#elif (_PLH_OS_DARWIN)

// the lazy-bind section is unprotected on darwin

bool
disableImportWriteProtection(
	void* module,
	ImportWriteProtectionBackup* backup
	)
{
	return true;
}

bool
disableImportWriteProtection(
	const ModuleIterator& moduleIterator,
	ImportWriteProtectionBackup* backup
	)
{
	return true;
}

bool
restoreImportWriteProtection(const ImportWriteProtectionBackup* backup)
{
	return true;
}

#endif

//..............................................................................

} // namespace plh
