#pragma once

#include "plh_ModuleEnumerator.h"
#include <string.h>

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

	ImportWriteProtectionBackup()
	{
		memset(this, 0, sizeof(ImportWriteProtectionBackup));
	}
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
