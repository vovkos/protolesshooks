#include "plh_ImportWriteProtection.h"
#include "plh_ModuleEnumerator.h"
#include "plh_Os.h"

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
	link_map* linkMap = (link_map*)module;
	size_t moduleBase = (size_t)linkMap->l_addr;
	ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)moduleBase;

	size_t p = moduleBase + ehdr->e_phoff;
	for (size_t i = 0; i < ehdr->e_phnum; i++, p += ehdr->e_phentsize)
	{
		ElfW(Phdr)* phdr = (ElfW(Phdr)*)p;
		if (phdr->p_type != PT_GNU_RELRO) // read-only-after-relocation (contains GOT)
			continue;

		size_t begin = moduleBase + phdr->p_vaddr;
		size_t end = begin + phdr->p_memsz;

		size_t pageSize = g::getModule()->getSystemInfo()->m_pageSize;
		begin &= ~(pageSize - 1);
		end = (end + pageSize - 1) & ~(pageSize - 1);

		backup->m_p = (char*)begin;
		backup->m_size = end - begin;
		backup->m_flags = phdr->p_flags;

		int result = ::mprotect(backup->m_p, backup->m_size, PROT_READ | PROT_WRITE | PROT_EXEC);
		return err::complete(result != -1);
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
	return err::complete(result != -1);
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
