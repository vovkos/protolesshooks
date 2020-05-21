#include "plh_ImportEnumerator.h"
#include <stdio.h>

#if (_PLH_OS_WIN)
#	include <windows.h>
#	include <psapi.h>
#elif (_PLH_OS_DARWIN)
#	include "plh_Leb128.h"
#	include <mach-o/loader.h>
#endif

namespace plh {

//..............................................................................

void
ImportIteratorBase::reset()
{
	m_symbolName = NULL;
	m_moduleName = NULL;
	m_slot = NULL;
}

//..............................................................................

#if (_WIN32)
#	define _PLH_SPY_USE_RAW_SIZE 1
#	if (_DEBUG)
#		define _PLH_SPY_TRACE_NON_CODE_IMPORT    1
#		define _PLH_SPY_ANALYZE_NON_CODE_ADDRESS 1
#	endif

IMAGE_NT_HEADERS*
getPeHdr(HMODULE hModule)
{
	char* moduleBase = (char*)hModule;

	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)moduleBase;
	if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	IMAGE_NT_HEADERS* peHdr = (IMAGE_NT_HEADERS*)(moduleBase + dosHdr->e_lfanew);
	if (peHdr->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return peHdr;
}

//..............................................................................

bool
PeCodeMap::isCode(size_t address)
{
	ModuleCodeMap* map = getModuleCodeMap(address);
	if (!map)
		return false;

	if (map->m_codeSection.isInside(address))
		return true;

	size_t count = map->m_auxCodeSectionArray.size();
	for (size_t i = 0; i < count; i++)
		if (map->m_auxCodeSectionArray[i].isInside(address))
			return true;

	return false;
}

#if (_PLH_SPY_ANALYZE_NON_CODE_ADDRESS)

void
PeCodeMap::analyzeNonCodeAddress(size_t address)
{
	ModuleCodeMap* map = getModuleCodeMap(address);
	if (!map)
	{
		printf("  *** parent module not found for %p\n", (void*)address);
		return;
	}

	HMODULE hModule = (HMODULE)map->m_moduleBase;

	wchar_t baseName[256];
	wchar_t fileName[256];
	::GetModuleBaseNameW(::GetCurrentProcess(), hModule, baseName, sizeof(baseName));
	::GetModuleFileNameW(hModule, fileName, sizeof(fileName));

	size_t rva = address - map->m_moduleBase;

	printf(
		"  address:     %p\n"
		"  RVA:         %p\n"
		"  module:\n"
		"    baseName:  %S\n"
		"    fileName:  %S\n"
		"    begin:     %p\n"
		"    end:       %p\n"
		"    size:      %zd\n"
		"  sections:\n",
		(void*)address,
		(void*)rva,
		baseName,
		fileName,
		(void*)map->m_moduleBase,
		(void*)map->m_moduleEnd,
		map->m_moduleEnd - map->m_moduleBase
		);

	IMAGE_NT_HEADERS* peHdr = getPeHdr(hModule);
	if (!peHdr)
	{
		printf("  *** can't get PE header\n");
		return;
	}

	IMAGE_SECTION_HEADER* p = IMAGE_FIRST_SECTION(peHdr);
	IMAGE_SECTION_HEADER* end = p + peHdr->FileHeader.NumberOfSections;

	size_t moduleBase = (size_t)hModule;
	for (; p < end; p++)
	{
		DWORD sectionEnd = p->VirtualAddress + p->Misc.VirtualSize;

		printf(
			"    %c%8s: %08x .. %08x\n",
			rva >= p->VirtualAddress && rva < sectionEnd ? '>' : ' ',
			p->Name,
			p->VirtualAddress,
			sectionEnd
			);
	}
}

#endif

PeCodeMap::ModuleCodeMap*
PeCodeMap::getModuleCodeMap(size_t address)
{
	if (!m_moduleMap.empty())
	{
		std::map<size_t, ModuleCodeMap>::iterator it = m_moduleMap.lower_bound(address);
		it--; // strictly less

		if (it != m_moduleMap.end() && address < it->second.m_moduleEnd)
			return &it->second;
	}

	HMODULE hModule;
	MODULEINFO moduleInfo;

	BOOL result =
		::GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
			(LPCWSTR)address,
			&hModule
			) &&
		::GetModuleInformation(
			::GetCurrentProcess(),
			hModule,
			&moduleInfo,
			sizeof(moduleInfo)
			);

	if (!result)
		return NULL;

	assert(moduleInfo.lpBaseOfDll == hModule);

	IMAGE_NT_HEADERS* peHdr = getPeHdr(hModule);
	if (!peHdr)
		return false;

	size_t moduleBase = (size_t)hModule;
	ModuleCodeMap* map = &m_moduleMap[moduleBase];
	map->m_moduleBase = moduleBase;
	map->m_moduleEnd = moduleBase + moduleInfo.SizeOfImage;
	map->m_codeSection.m_begin = 0;
	map->m_codeSection.m_end = 0;

	IMAGE_SECTION_HEADER* p = IMAGE_FIRST_SECTION(peHdr);
	IMAGE_SECTION_HEADER* end = p + peHdr->FileHeader.NumberOfSections;

	for (; p < end; p++)
	{
		if (!(p->Characteristics & IMAGE_SCN_CNT_CODE))
			continue;

		AddressRange range;
		range.m_begin = moduleBase + p->VirtualAddress;
#if (_PLH_SPY_USE_RAW_SIZE) // normally, shouldn't matter
		range.m_end = range.m_begin + p->SizeOfRawData;
#else
		range.m_end = range.m_begin + p->Misc.VirtualSize;
#endif

		if (!map->m_codeSection.m_begin)
			map->m_codeSection = range;
		else
			map->m_auxCodeSectionArray.push_back(range);
	}

	return map;
}

//..............................................................................

ImportIterator::ImportIterator()
{
	m_ordinal = -1;
	m_importDescIdx = -1;
	m_nameThunk = NULL;
	m_addrThunk = NULL;
}

ImportIterator::ImportIterator(std::shared_ptr<PeImportEnumeration>&& enumeration)
{
	m_ordinal = -1;
	m_importDescIdx = -1;
	m_nameThunk = NULL;
	m_addrThunk = NULL;

	if (!enumeration)
		return;

	m_enumeration = enumeration;
	m_importDescIdx = 0;
	openImportDesc();
}

ImportIterator&
ImportIterator::operator ++ ()
{
	if (!m_enumeration || m_importDescIdx >= m_enumeration->m_importDescCount)
	{
		reset();
		return *this;
	}

	assert(m_nameThunk && m_addrThunk);
	m_nameThunk++;
	m_addrThunk++;

	bool result = readThunk();
	if (!result)
	{
		m_importDescIdx++;
		openImportDesc();
	}

	return *this;
}

bool
ImportIterator::openImportDesc()
{
	assert(m_enumeration);

	bool result;

	for (; m_importDescIdx < m_enumeration->m_importDescCount; m_importDescIdx++)
	{
		IMAGE_IMPORT_DESCRIPTOR* p = &m_enumeration->m_importDir[m_importDescIdx];
		if (!p->Name) // NULL-terminator
			break;

		m_nameThunk = (IMAGE_THUNK_DATA*)(m_enumeration->m_moduleBase + p->OriginalFirstThunk);
		m_addrThunk = (IMAGE_THUNK_DATA*)(m_enumeration->m_moduleBase + p->FirstThunk);

		result = readThunk();
		if (result)
		{
			m_moduleName = m_enumeration->m_moduleBase + p->Name;
			return true;
		}
	}

	reset();
	return false;
}

bool
ImportIterator::readThunk()
{
	assert(m_enumeration && m_nameThunk && m_addrThunk);

	for (; m_addrThunk->u1.Function; m_nameThunk++, m_addrThunk++)
	{
		if (IMAGE_SNAP_BY_ORDINAL(m_nameThunk->u1.Ordinal))
		{
			m_ordinal = IMAGE_ORDINAL(m_nameThunk->u1.Ordinal);
			m_symbolName = NULL;
		}
		else
		{
			IMAGE_IMPORT_BY_NAME* name = (IMAGE_IMPORT_BY_NAME*)(m_enumeration->m_moduleBase + m_nameThunk->u1.AddressOfData);
			m_ordinal = -1;
			m_hint = name->Hint;
			m_symbolName = (char*)name->Name;
		}

		if (!isCode(m_addrThunk->u1.Function))
		{
#if (_PLH_SPY_TRACE_NON_CODE_IMPORT)
			if (m_ordinal != -1)
				printf("Non-code import: %s@%d\n", m_moduleName, m_ordinal);
			else
				printf("Non-code import: %s:%s\n", m_moduleName, m_symbolName);
#	if (_PLH_SPY_ANALYZE_NON_CODE_ADDRESS)
			m_codeMap->analyzeNonCodeAddress(m_addrThunk->u1.Function);
#	endif
#endif
			continue;
		}

		m_slot = (void**)&m_addrThunk->u1.Function; // not RVA!
		return true;
	}

	return false;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
enumerateImports(
	ImportIterator* iterator,
	void* module
	)
{
	if (!module)
		module = ::GetModuleHandle(NULL);

	IMAGE_NT_HEADERS* peHdr = getPeHdr((HMODULE)module);
	if (!peHdr)
		return false;

	char* moduleBase = (char*)module;
	IMAGE_DATA_DIRECTORY* importDir = (IMAGE_DATA_DIRECTORY*)&peHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	std::shared_ptr<PeImportEnumeration> enumeration = std::make_shared<PeImportEnumeration>();
	enumeration->m_moduleBase = moduleBase;
	enumeration->m_importDir = (IMAGE_IMPORT_DESCRIPTOR*)(moduleBase + importDir->VirtualAddress);
	enumeration->m_importDescCount = importDir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	*iterator = ImportIterator(std::move(enumeration));
	return true;
}

bool
enumerateImports(
	ImportIterator* importIterator,
	const ModuleIterator& moduleIterator
	)
{
	return enumerateImports(importIterator, moduleIterator.getModule());
}

#elif (_PLH_OS_LINUX)

ImportIterator::ImportIterator(std::shared_ptr<ElfImportEnumeration>&& enumeration)
{
	if (!enumeration)
	{
		m_index = -1;
		return;
	}

	m_enumeration = enumeration;
	m_index = 0;
	readRel();
}

ImportIterator&
ImportIterator::operator ++ ()
{
	if (!m_enumeration ||
		m_index >= m_enumeration->m_pltRelCount + m_enumeration->m_gotRelCount)
	{
		reset();
		return *this;
	}

	m_index++;
	readRel();
	return *this;
}

bool
ImportIterator::readRel()
{
	assert(m_enumeration && "attempt to read ElfRel from a null-iterator");

	int relType;
	ElfRel* rel;
	ElfRel* end;

	if (m_index < m_enumeration->m_pltRelCount)
	{
		relType = R_JUMP_SLOT;
		rel = m_enumeration->m_pltRelTable;
		end = rel + m_enumeration->m_pltRelCount;
		rel += m_index;
	}
	else
	{
		relType = R_GLOB_DAT;
		rel = m_enumeration->m_gotRelTable;
		end = rel + m_enumeration->m_gotRelCount;
		rel += m_index - m_enumeration->m_pltRelCount;
	}

	for (; rel < end; rel++, m_index++)
	{
		if (ELF_R_TYPE(rel->r_info) != relType)
			continue;

		size_t symIdx = ELF_R_SYM(rel->r_info);
		ElfW(Sym)* sym = m_enumeration->m_symbolTable + symIdx;
		if (ELF_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		if (sym->st_name >= m_enumeration->m_stringTableSize)
		{
			printf("WARNING: ImportIterator::readRel: symbol out of string table\n");
			continue;
		}

		m_symbolName = m_enumeration->m_stringTable + sym->st_name;
		m_slot = (void**)(m_enumeration->m_baseAddress + rel->r_offset);
		return true;
	}

	if (relType == R_JUMP_SLOT)
		return readRel(); // retry with GOT

	reset();
	return false;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
enumerateImports(
	ImportIterator* iterator,
	void* module
	)
{
	link_map* linkMap = module ? (link_map*)module : _r_debug.r_map;

	ElfW(Dyn)* dynTable[DT_NUM] = { 0 };
	ElfW(Dyn)* dyn = linkMap->l_ld;
	for (; dyn->d_tag; dyn++)
		if (dyn->d_tag < DT_NUM)
			dynTable[dyn->d_tag] = dyn;

	// sanity check

	if (!dynTable[DT_SYMTAB] ||
		!dynTable[DT_SYMENT] ||
		!dynTable[DT_STRTAB] ||
		!dynTable[DT_STRSZ] ||
		!dynTable[DT_GOT_REL] != !dynTable[DT_GOT_RELSZ] ||
		!dynTable[DT_GOT_REL] != !dynTable[DT_GOT_RELENT] ||
		!dynTable[DT_JMPREL] != !dynTable[DT_PLTRELSZ] ||
		dynTable[DT_SYMENT]->d_un.d_val != sizeof(ElfW(Sym)) ||
		dynTable[DT_GOT_RELENT] && dynTable[DT_GOT_RELENT]->d_un.d_val != sizeof(ElfRel))
		return false;

	size_t pltRelCount = dynTable[DT_PLTRELSZ] ? dynTable[DT_PLTRELSZ]->d_un.d_val / sizeof(ElfRel) : 0;
	size_t gotRelCount = dynTable[DT_GOT_RELSZ] ? dynTable[DT_GOT_RELSZ]->d_un.d_val / sizeof(ElfRel) : 0;

	if (!pltRelCount && !gotRelCount)
	{
		*iterator = ImportIterator();
		return true;
	}

	std::shared_ptr<ElfImportEnumeration> enumeration = std::make_shared<ElfImportEnumeration>();
	enumeration->m_baseAddress = linkMap->l_addr;
	enumeration->m_symbolTable = (ElfW(Sym)*)dynTable[DT_SYMTAB]->d_un.d_ptr;
	enumeration->m_stringTable = (char*)dynTable[DT_STRTAB]->d_un.d_ptr;
	enumeration->m_stringTableSize = dynTable[DT_STRSZ]->d_un.d_val;
	enumeration->m_pltRelTable = dynTable[DT_JMPREL] ? (ElfRel*)dynTable[DT_JMPREL]->d_un.d_ptr : NULL;
	enumeration->m_pltRelCount = pltRelCount;
	enumeration->m_gotRelTable = dynTable[DT_GOT_REL] ? (ElfRel*)dynTable[DT_GOT_REL]->d_un.d_ptr : NULL;
	enumeration->m_gotRelCount = gotRelCount;

	*iterator = ImportIterator(std::move(enumeration));
	return true;
}

bool
enumerateImports(
	ImportIterator* importIterator,
	const ModuleIterator& moduleIterator
	)
{
	return enumerateImports(importIterator, moduleIterator.getModule());
}

#elif (_PLH_OS_DARWIN)

ImportIterator::ImportIterator(std::shared_ptr<ImportEnumeration>&& enumeration)
{
	init();
	m_enumeration = enumeration;
	next();
}

void
ImportIterator::setState(
	State state,
	const char* begin,
	size_t size
	)
{
	m_state = state;
	m_slot = NULL;
	m_slotVmAddr = 0;
	m_moduleName = NULL;
	m_symbolName = NULL;
	m_segmentName = NULL;
	m_sectionName = NULL;
	m_begin = begin;
	m_end = begin + size;
	m_p = begin;
	m_segmentIdx = 0;
	m_segmentOffset = 0;
}

ImportIterator&
ImportIterator::operator ++ ()
{
	if (!m_enumeration || m_state == State_Done)
	{
		reset();
		return *this;
	}

	next();
	return *this;
}

// bind-opcode handling logic is taken from dyldinfo.cpp

bool
ImportIterator::next()
{
	m_slot = NULL;

	while (!m_pendingSlotArray.empty())
	{
		size_t slotVmAddr = m_pendingSlotArray.back();
		m_pendingSlotArray.pop_back();
		setSlot(slotVmAddr);
		if (m_slot)
			return true;
	}

	do
	{
		bool isDone = false;
		size_t bindOffsetDelta = m_state == State_LazyBind ? 0 : sizeof(void*);

		while (m_p < m_end && !m_slot && !isDone)
		{
			uint8_t c = *m_p++;
			uint8_t op = c & BIND_OPCODE_MASK;
			uint8_t imm = c & BIND_IMMEDIATE_MASK;
			int64_t sleb;
			uint64_t uleb;
			uint64_t skip;

			switch (op)
			{
			case BIND_OPCODE_DONE:
				if (m_state != State_LazyBind)
					isDone = true;
				else
					m_segmentOffset = m_p - m_begin;
				break;

			case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
				m_moduleName = getDylibName(imm);
				break;

			case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
				m_p += uleb128(m_p, m_end - m_p, &uleb);
				m_moduleName = getDylibName(uleb);
				break;

			case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
				m_moduleName = getDylibName(imm ? BIND_OPCODE_MASK | imm : 0);
				break;

			case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
				m_symbolName = m_p;
				m_p += strlen(m_p) + 1;
				break;

			case BIND_OPCODE_SET_TYPE_IMM:
				break;

			case BIND_OPCODE_SET_ADDEND_SLEB:
				m_p += sleb128(m_p, m_end - m_p, &sleb);
				break;

			case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				m_p += uleb128(m_p, m_end - m_p, &uleb);
				m_segmentIdx = imm;
				m_segmentOffset = uleb;
				break;

			case BIND_OPCODE_ADD_ADDR_ULEB:
				m_p += uleb128(m_p, m_end - m_p, &uleb);
				m_segmentOffset += uleb;
				break;

			case BIND_OPCODE_DO_BIND:
				bind();
				m_segmentOffset += bindOffsetDelta;
				break;

			case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
				m_p += uleb128(m_p, m_end - m_p, &uleb);
				bind();
				m_segmentOffset += uleb + bindOffsetDelta;
				break;

			case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
				bind();
				m_segmentOffset += imm * sizeof(void*) + bindOffsetDelta;
				break;

			case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
				m_p += uleb128(m_p, m_end - m_p, &uleb);
				m_p += uleb128(m_p, m_end - m_p, &skip);
				skip += bindOffsetDelta;

				for (uint64_t i = 0; i < uleb; i++)
				{
					bind();
					m_segmentOffset += skip;
				}

				break;

			default:
				printf("WARNING: unexpected bind op: 0x%02x\n", op);
			}
		}

		if (m_slot)
			return true;

		// advance to the next bind kind

		switch (m_state)
		{
		case State_Idle:
			setState(
				State_Bind,
				m_enumeration->m_linkEditSegmentBase + m_enumeration->m_dyldInfoCmd->bind_off,
				m_enumeration->m_dyldInfoCmd->bind_size
				);
			break;

		case State_Bind:
			setState(
				State_WeakBind,
				m_enumeration->m_linkEditSegmentBase + m_enumeration->m_dyldInfoCmd->weak_bind_off,
				m_enumeration->m_dyldInfoCmd->weak_bind_size
				);
			break;

		case State_WeakBind:
			setState(
				State_LazyBind,
				m_enumeration->m_linkEditSegmentBase + m_enumeration->m_dyldInfoCmd->lazy_bind_off,
				m_enumeration->m_dyldInfoCmd->lazy_bind_size
				);
			break;

		case State_LazyBind:
			setState(State_Done,NULL, 0);
			break;

		default:
			assert(false && "invalid state inside the 'next' loop");
			break;
		}

		m_p = m_begin;
	} while (m_state != State_Done);

	assert(!m_slot && "at the end of binding info with a non-null slot");
	return false;
}

bool
ImportIterator::bind()
{
	if (m_segmentIdx >= m_enumeration->m_segmentArray.size())
		return false;

	const segment_command_64* segment = m_enumeration->m_segmentArray[m_segmentIdx];
	if (m_segmentOffset >= segment->vmsize)
		return false;

	m_segmentName = segment->segname;

	size_t slotVmAddr = segment->vmaddr + m_segmentOffset;
	if (!m_slot)
	{
		setSlot(slotVmAddr);
		return m_slot != NULL;
	}

	m_pendingSlotArray.push_back(slotVmAddr);
	return true;
}

bool
ImportIterator::setSlot(size_t slotVmAddr)
{
	assert(m_segmentIdx < m_enumeration->m_segmentArray.size() && "segment index out-of-bounds");
	const segment_command_64* segment = m_enumeration->m_segmentArray[m_segmentIdx];

	const section_64* section = findSection(segment, slotVmAddr);
	if (!section) // wrong section type
		return false;

	uint8_t sectionType = section->flags & SECTION_TYPE;
	if (sectionType != S_LAZY_SYMBOL_POINTERS) // wrong section type
		return false;

	m_slot = (void**)(m_enumeration->m_slide + slotVmAddr);
	m_slotVmAddr = slotVmAddr;
	m_sectionName = section->sectname;
	return true;
}

const section_64*
ImportIterator::findSection(
	const segment_command_64* segment,
	size_t slotVmAddr
	)
{
	const section_64* section = (section_64*)(segment + 1);
	const section_64* end = section + segment->nsects;
	for (; section < end; section++)
		if (slotVmAddr >= section->addr && slotVmAddr < section->addr + section->size)
			return section;

	return NULL;
}

const char*
ImportIterator::getDylibName(int ordinal)
{
	switch (ordinal)
	{
	case BIND_SPECIAL_DYLIB_SELF:
		return "this-image";

	case BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
		return "main-executable";

	case BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
		return "flat-namespace";
	}

	return
		ordinal < 0 ? "unknown-special-ordinal" :
		ordinal <= m_enumeration->m_dylibNameArray.size() ? m_enumeration->m_dylibNameArray[ordinal - 1] :
		"dylib-index-out-of-range";
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

bool
enumerateImports(
	ImportIterator* iterator,
	size_t imageIndex
	)
{
	char* slide = (char*)::_dyld_get_image_vmaddr_slide(imageIndex);
	mach_header_64* machHdr = (mach_header_64*)::_dyld_get_image_header(imageIndex);

	std::vector<struct segment_command_64*> segmentArray;
	std::vector<const char*> dylibNameArray;
	segment_command_64* linkEditSegmentCmd = NULL;
	dyld_info_command* dyldInfoCmd = NULL;

	load_command* cmd = (load_command*)(machHdr + 1);
	for (size_t i = 0; i < machHdr->ncmds; i++)
	{
		segment_command_64* segmentCmd;
		dylib_command* dylibCmd;
		switch (cmd->cmd)
		{
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_REEXPORT_DYLIB:
		case LC_LOAD_UPWARD_DYLIB:
		case LC_LAZY_LOAD_DYLIB:
			dylibCmd = (dylib_command*)cmd;
			dylibNameArray.push_back((char*)cmd + dylibCmd->dylib.name.offset);
			break;

		case LC_SEGMENT_64:
			segmentCmd = (segment_command_64*)cmd;
			segmentArray.push_back(segmentCmd);

			if (strcmp(segmentCmd->segname, "__LINKEDIT") == 0)
				linkEditSegmentCmd = segmentCmd;

			break;

		case LC_DYLD_INFO_ONLY:
			dyldInfoCmd = (dyld_info_command*)cmd;
			break;
		}

		cmd = (load_command*)((char*)cmd + cmd->cmdsize);
	}

	if (!linkEditSegmentCmd || !dyldInfoCmd)
		return false;

	std::shared_ptr<ImportEnumeration> enumeration = std::make_shared<ImportEnumeration>();
	enumeration->m_segmentArray = segmentArray;
	enumeration->m_dylibNameArray = dylibNameArray;
	enumeration->m_slide = slide;
	enumeration->m_linkEditSegmentBase = slide + linkEditSegmentCmd->vmaddr - linkEditSegmentCmd->fileoff;
	enumeration->m_dyldInfoCmd = dyldInfoCmd;

	*iterator = ImportIterator(std::move(enumeration));
	return true;
}

bool
enumerateImports(
	ImportIterator* importIterator,
	const ModuleIterator& moduleIterator
	)
{
	return enumerateImports(importIterator, moduleIterator.getImageIndex());
}

bool
enumerateImports(
	ImportIterator* iterator,
	void* module
	)
{
	size_t i = 0;
	size_t count = _dyld_image_count();
	for (size_t i = 0; i < count; i++)
	{
		DynamicLib lib;
		const char* imageName = _dyld_get_image_name(i);
		bool result = lib.open(imageName, RTLD_NOLOAD);
		if (result && lib == module)
			return enumerateImports(iterator, i);
	}

	return false;
}

#endif

//..............................................................................

ImportIterator
ImportIterator::operator ++ (int)
{
	ImportIterator it = *this;
	operator ++ ();
	return it;
}

//..............................................................................

} // namespace plh
