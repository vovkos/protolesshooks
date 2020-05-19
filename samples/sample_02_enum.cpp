#include "plh_ModuleEnumerator.h"
#include "plh_ImportEnumerator.h"
#include <stdio.h>

//..............................................................................

int
main()
{
	plh::ModuleIterator moduleIt = plh::enumerateModules();
	for (; moduleIt; moduleIt++)
	{
		printf("Module %s imports:\n", moduleIt.getModuleFileName());

		plh::ImportIterator importIt = plh::enumerateImports(moduleIt);
		for (; importIt; importIt++)
		{
#if (_PLH_OS_WIN)
			if (importIt.getOrdinal() != -1)
				printf("  %s@%d\n", importIt.getModuleName(), importIt.getOrdinal());
			else
				printf("  %s:%s\n", importIt.getModuleName(), importIt.getSymbolName());
#elif (_PLH_OS_LINUX)
			printf("  %s\n", importIt.getSymbolName());
#elif (_PLH_OS_DARWIN)
			printf(
				"  %s:%s...\n",
				importIt.getModuleName(),
				importIt.getSymbolName()
				);
#endif
		}
	}

	return 0;
}

//..............................................................................
