#pragma once

#include "plh_ModuleEnumerator.h"
#include <memory>

#if (_PLH_OS_WIN)
#	include <vector>
#	include <map>
#elif (_PLH_OS_LINUX)
#	if (_PLH_CPU_X86)
#	    define ELF_R_TYPE    ELF32_R_TYPE
#	    define ELF_R_SYM     ELF32_R_SYM
#	    define ELF_ST_TYPE   ELF32_ST_TYPE
#	    define ELF_ST_BIND   ELF32_ST_BIND

#       define DT_GOT_REL    DT_REL
#       define DT_GOT_RELSZ  DT_RELSZ
#       define DT_GOT_RELENT DT_RELENT

#		define R_GLOB_DAT     R_386_GLOB_DAT
#		define R_JUMP_SLOT    R_386_JMP_SLOT

typedef ElfW(Rel) ElfRel;

#	elif (_PLH_CPU_AMD64)
#	    define ELF_R_TYPE    ELF64_R_TYPE
#	    define ELF_R_SYM     ELF64_R_SYM
#	    define ELF_ST_TYPE   ELF64_ST_TYPE
#	    define ELF_ST_BIND   ELF64_ST_BIND

#       define DT_GOT_REL    DT_RELA
#       define DT_GOT_RELSZ  DT_RELASZ
#       define DT_GOT_RELENT DT_RELAENT

#       define R_GLOB_DAT    R_X86_64_GLOB_DAT
#       define R_JUMP_SLOT   R_X86_64_JUMP_SLOT

typedef ElfW(Rela) ElfRel;

#	elif (_PLH_CPU_ARM32)
#	    define ELF_R_TYPE    ELF32_R_TYPE
#	    define ELF_R_SYM     ELF32_R_SYM
#	    define ELF_ST_TYPE   ELF32_ST_TYPE
#	    define ELF_ST_BIND   ELF32_ST_BIND

#       define DT_GOT_REL    DT_REL
#       define DT_GOT_RELSZ  DT_RELSZ
#       define DT_GOT_RELENT DT_RELENT

#       define R_GLOB_DAT    R_ARM_GLOB_DAT
#       define R_JUMP_SLOT   R_ARM_JUMP_SLOT

	typedef ElfW(Rel) ElfRel;

#	endif
#elif (_PLH_OS_DARWIN)
#	include <vector>
#	include <mach-o/dyld.h>
#	include <mach-o/loader.h>
#endif

namespace plh {

//..............................................................................

class ImportIteratorBase
{
protected:
	const char* m_symbolName;
	const char* m_moduleName;
	void** m_slot;

public:
	ImportIteratorBase()
	{
		m_slot = NULL;
	}

	operator bool ()
	{
		return m_slot != NULL;
	}

	const char*
	getSymbolName() const
	{
		return m_symbolName;
	}

	const char*
	getModuleName() const
	{
		return m_moduleName;
	}

	void**
	getSlot() const
	{
		return m_slot;
	}

protected:
	void
	reset();
};

#if (_PLH_OS_WIN)

//..............................................................................

class PeCodeMap
{
protected:
	struct AddressRange
	{
		size_t m_begin;
		size_t m_end;

		bool
		isInside(size_t address)
		{
			return address >= m_begin && address < m_end;
		}
	};

	struct ModuleCodeMap
	{
		size_t m_moduleBase;
		size_t m_moduleEnd;
		AddressRange m_codeSection;
		std::vector<AddressRange> m_auxCodeSectionArray;
	};

protected:
	std::map<size_t, ModuleCodeMap> m_moduleMap;

public:
	bool
	isCode(size_t address);

	void
	analyzeNonCodeAddress(size_t address);

protected:
	ModuleCodeMap*
	getModuleCodeMap(size_t address);
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

struct PeImportEnumeration
{
	char* m_moduleBase;
	IMAGE_IMPORT_DESCRIPTOR* m_importDir;
	size_t m_importDescCount;
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

class ImportIterator: public ImportIteratorBase
{
protected:
	uint32_t m_ordinal;
	uint32_t m_hint;

	std::shared_ptr<PeImportEnumeration> m_enumeration;
	std::shared_ptr<PeCodeMap> m_codeMap;
	size_t m_importDescIdx;
	IMAGE_THUNK_DATA* m_nameThunk;
	IMAGE_THUNK_DATA* m_addrThunk;

public:
	ImportIterator();
	ImportIterator(std::shared_ptr<PeImportEnumeration>&& enumeration);

	ImportIterator&
	operator ++ ();

	ImportIterator
	operator ++ (int);

	uint32_t
	getOrdinal()
	{
		return m_ordinal;
	}

	uint32_t
	getHint()
	{
		return m_hint;
	}

protected:
	bool
	openImportDesc();

	bool
	isCode(size_t address)
	{
		return (m_codeMap ? m_codeMap : m_codeMap = std::make_shared<PeCodeMap>())->isCode(address);
	}

	bool
	readThunk();
};

#elif (_PLH_OS_LINUX)

//..............................................................................

struct ElfImportEnumeration
{
	size_t m_baseAddress; // relocation difference, not an absolute address
	ElfW(Sym)* m_symbolTable;
	char* m_stringTable;
	size_t m_stringTableSize;
	ElfRel* m_pltRelTable;
	size_t m_pltRelCount;
	ElfRel* m_gotRelTable;
	size_t m_gotRelCount;
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

class ImportIterator: public ImportIteratorBase
{
protected:
	std::shared_ptr<ElfImportEnumeration> m_enumeration;
	size_t m_index;

public:
	ImportIterator()
	{
		m_index = -1;
	}

	ImportIterator(std::shared_ptr<ElfImportEnumeration>&& enumeration);

	ImportIterator&
	operator ++ ();

	ImportIterator
	operator ++ (int);

protected:
	bool
	readRel();
};

#elif (_PLH_OS_DARWIN)

struct ImportEnumeration
{
	std::vector<segment_command_64*> m_segmentArray;
	std::vector<const char*> m_dylibNameArray;
	char* m_slide;
	char* m_linkEditSegmentBase;
	dyld_info_command* m_dyldInfoCmd;
};

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

class ImportIterator: public ImportIteratorBase
{
protected:
	enum State
	{
		State_Idle,
		State_Bind,
		State_WeakBind,
		State_LazyBind,
		State_Done,
	};

protected:
	size_t m_slotVmAddr;
	const char* m_segmentName;
	const char* m_sectionName;

	std::shared_ptr<ImportEnumeration> m_enumeration;
	std::vector<size_t> m_pendingSlotArray; // from BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
	State m_state;
	const char* m_p;
	const char* m_begin;
	const char* m_end;
	size_t m_segmentIdx;
	size_t m_segmentOffset;

public:
	ImportIterator()
	{
		init();
	}

	ImportIterator(std::shared_ptr<ImportEnumeration>&& enumeration);

	ImportIterator&
	operator ++ ();

	ImportIterator
	operator ++ (int);

	const char*
	getSegmentName() const
	{
		return m_segmentName;
	}

	const char*
	getSectionName() const
	{
		return m_sectionName;
	}

	size_t
	getSlotVmAddr()
	{
		return m_slotVmAddr;
	}

protected:
	void
	init()
	{
		setState(State_Idle, NULL, 0);
	}

	void
	setState(
		State state,
		const char* p,
		size_t size
		);

	bool
	next();

	bool
	bind();

	bool
	setSlot(size_t slotVmAddr);

	const struct section_64*
	findSection(
		const struct segment_command_64* segment,
		size_t slotVmAddr
		);

	const char*
	getDylibName(int ordinal);
};

#endif

//..............................................................................

bool
enumerateImports(
	ImportIterator* iterator,
	void* module = NULL
	);

bool
enumerateImports(
	ImportIterator* importIterator,
	const ModuleIterator& moduleIterator
	);

inline
ImportIterator
enumerateImports(void* module = NULL)
{
	ImportIterator iterator;
	enumerateImports(&iterator, module);
	return iterator;
}

inline
ImportIterator
enumerateImports(const ModuleIterator& moduleIterator)
{
	ImportIterator importIterator;
	enumerateImports(&importIterator, moduleIterator);
	return importIterator;
}

//..............................................................................

} // namespace plh
