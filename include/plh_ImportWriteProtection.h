#pragma once

#include "plh_ModuleEnumerator.h"
#include <stdint.h>

namespace plh {

//..............................................................................

struct ImportWriteProtectionBackup
{
	void* m_p;
	size_t m_size;

	union
	{
		int m_flags;              // ElfW(Phdr)->p_flags
		uint32_t m_oldProtection; // returned by VirtualProtect
	};
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
disableImportWriteProtection(
	void* module,
	ImportWriteProtectionBackup* backup
	);

bool
disableImportWriteProtection(
	const ModuleIterator& moduleIterator,
	ImportWriteProtectionBackup* backup
	);

bool
restoreImportWriteProtection(const ImportWriteProtectionBackup* backup);

//..............................................................................

} // namespace plh
