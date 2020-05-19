#include "plh_ModuleEnumerator.h"
#include "plh_ImportEnumerator.h"
#include "plh_ImportWriteProtection.h"
#include "plh_Hook.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <string>
#include <sstream>
#include <list>
#include <unordered_map>

#define _TRACE_HOOKING_MODULE   1
#define _TRACE_HOOKING_FUNCTION 1

//..............................................................................

size_t g_indentSlot;

int
incrementIndent(int delta)
{
	int indent = (int)plh::getTlsValue(g_indentSlot);
	plh::setTlsValue(g_indentSlot, indent + delta);
	return indent;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

plh::HookAction
hookEnter(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	int indent = incrementIndent(1);

	printf(
		"%*sTID %llx: sp: %p +%s\n",
		indent * 2,
		"",
		plh::getCurrentThreadId(),
		(void*)frameBase,
		(char*)callbackParam
		);


	return plh::HookAction_Default;
}

void
hookLeave(
	void* targetFunc,
	void* callbackParam,
	size_t frameBase
	)
{
	int indent = incrementIndent(-1) - 1;

	if (!frameBase) // abandoned
	{
		printf(
			"%*sTID %llx: ~%s\n",
			indent * 2,
			"",
			plh::getCurrentThreadId(),
			(char*)callbackParam
			);

		return;
	}

	plh::RegRetBlock* regRetBlock = (plh::RegRetBlock*)(frameBase + plh::FrameOffset_RegRetBlock);

#if (_PLH_CPU_AMD64)
	int returnValue = (int)regRetBlock->m_rax;
#elif (_PLH_CPU_X86)
	int returnValue = regRetBlock->m_eax;
#endif

	printf(
		"%*sTID %llx: sp: %p -%s -> %d/0x%x\n",
		indent * 2,
		"",
		plh::getCurrentThreadId(),
		(void*)frameBase,
		(char*)callbackParam,
		returnValue,
		returnValue
		);
}

const char*
getFileName(const char* fileName)
{
	if (!fileName)
		return "?";

	for (const char* p = fileName; *p; p++)
#if (_PLH_OS_WIN)
		if (*p == '/' || *p == '\\')
#else
		if (*p == '/')
#endif
			fileName = p + 1;

	return fileName;
}

bool
spyModule(
	const plh::ModuleIterator& moduleIt,
	plh::HookArena* hookArena,
	std::list<std::string>* stringCache
	)
{
	const char* moduleName = moduleIt.getModuleFileName();
#if (_TRACE_HOOKING_MODULE)
	printf("Hooking %s...\n", moduleName);
#endif

	moduleName = getFileName(moduleName);

#if (_PLH_OS_DARWIN)
	std::unordered_map<size_t, bool> hookSet;
#endif

	plh::ImportWriteProtectionBackup backup;
	bool result = plh::disableImportWriteProtection(moduleIt, &backup);
	if (!result)
		return false;

	static int32_t stringCacheFlag = 0;
	static int32_t hookArenaFlag = 0;

	plh::ImportIterator it = plh::enumerateImports(moduleIt);

	char const* currentModuleName = NULL;

	for (; it; it++)
	{
		stringCache->emplace_back();
		std::string& functionName = stringCache->back();
		const char* symbolName = it.getSymbolName();

#if (_PLH_OS_WIN)
		std::ostringstream sstream;
		sstream << moduleName;
		sstream << ":";
		sstream << it.getModuleName();
		sstream << ":";

		if (it.getOrdinal() == -1)
		{
			sstream << symbolName;
		}
		else
		{
			sstream << "@";
			sstream << it.getOrdinal();
		}

		functionName = sstream.str();

		if (symbolName &&
			(strcmp(symbolName, "TlsGetValue") == 0 ||
			strcmp(symbolName, "TlsSetValue") == 0))
		{
			printf("  skipping %s for now...\n", functionName.c_str());
			continue;
		}

		void** slot = it.getSlot();
		void* targetFunc = *slot;
		plh::Hook* hook = hookArena->allocate(targetFunc, (void*)functionName.c_str(), hookEnter, hookLeave);
#	if (_TRACE_HOOKING_FUNCTION)
		printf("  hooking [%p] %p -> %p %s...\n", slot, targetFunc, hook, functionName.c_str());
#	endif
		*slot = hook;
#elif (_PLH_OS_LINUX)
		functionName = moduleName;
		functionName += ":";
		functionName += symbolName;

		if (symbolName &&
			(strcmp(symbolName, "pthread_getspecific") == 0 ||
			strcmp(symbolName, "pthread_setspecific") == 0))
		{
			printf("  skipping %s for now...\n", functionName.c_str());
			continue;
		}

		void** slot = it.getSlot();
		void* targetFunc = *slot;
		plh::Hook* hook = hookArena->allocate(targetFunc, (void*)functionName.c_str(), hookEnter, hookLeave);
#	if (_TRACE_HOOKING_FUNCTION)
		printf("  hooking [%p] %p -> %p %s...\n", slot, targetFunc, hook, functionName.c_str());
#	endif
		*slot = hook;
#elif (_PLH_OS_DARWIN)
		functionName = moduleName;
		functionName += ":";
		functionName += getFileName(it.getModuleName());
		functionName += ":";
		functionName += symbolName;

		if (symbolName &&
			(strcmp(symbolName, "_pthread_getspecific") == 0 ||
			strcmp(symbolName, "_pthread_setspecific") == 0))
		{
			printf("  skipping %s for now...\n", functionName.c_str());
			continue;
		}

		size_t slotVmAddr = it.getSlotVmAddr();
		std::unordered_map<size_t, bool>::value_type hookSetValue(slotVmAddr, true);
		std::pair<std::unordered_map<size_t, bool>::iterator, bool> insertResult = hookSet.insert(hookSetValue);
		if (!insertResult.second)
		{
#	if (_TRACE_HOOKING_FUNCTION)
			printf("  already hooked [%08zx] %s\n", slotVmAddr, functionName.c_str());
#	endif
			continue;
		}

		void** slot = it.getSlot();
		void* targetFunc = *slot;
		plh::Hook* hook = hookArena->allocate(targetFunc, (void*)functionName.c_str(), hookEnter, hookLeave);
#	if (_TRACE_HOOKING_FUNCTION)
		printf(
			"  hooking [%08zx] %p -> %p %s...\n",
			slotVmAddr,
			targetFunc,
			hook,
			functionName.c_str()
			);
#	endif
		*slot = hook;
#endif
	}

	result = plh::restoreImportWriteProtection(&backup);
	assert(result);
	return true;
}

// . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

int
main()
{
	g_indentSlot = plh::createTlsSlot();

	plh::HookArena hookArena;
	std::list<std::string>* stringCache = new std::list<std::string>; // no free

	plh::ModuleIterator it = plh::enumerateModules();
	for (; it; it++)
		spyModule(it, &hookArena, stringCache);

	printf("Hooking done, enabling hooks...\n");
	plh::enableHooks();

	// puts/printf below will mess up the output; let's use something else...

	std::string* p = new std::string;
	delete p;

	return 0;
}

//..............................................................................
