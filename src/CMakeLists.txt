#...............................................................................

# .asm files are not compiled directly; we add them just for convenient editing

set(
	H_LIST
	${PLH_INC_DIR}/plh_Def.h
	${PLH_INC_DIR}/plh_Os.h
	${PLH_INC_DIR}/plh_Leb128.h
	${PLH_INC_DIR}/plh_ExecutableBlockArena.h
	${PLH_INC_DIR}/plh_ModuleEnumerator.h
	${PLH_INC_DIR}/plh_ImportEnumerator.h
	${PLH_INC_DIR}/plh_ImportWriteProtection.h
	${PLH_INC_DIR}/plh_Hook.h
	plh_HookCommon.h
	plh_ThreadState.h
	)

set(
	CPP_LIST
	plh_Os.cpp
	plh_Leb128.cpp
	plh_ModuleEnumerator.cpp
	plh_ImportEnumerator.cpp
	plh_ImportWriteProtection.cpp
	plh_HookCommon.cpp
	plh_ThreadState.cpp
	)

set (
	ASM_LIST
	plh_thunk_x86.asm
	plh_thunk_amd64_msc.asm
	plh_thunk_amd64_gcc.asm
	)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(
		CPP_LIST
		${CPP_LIST}
		plh_Hook_x86.cpp
		)
elseif(WIN32)
	set(
		CPP_LIST
		${CPP_LIST}
		plh_Hook_amd64_msc.cpp
		)
else()
	set(
		CPP_LIST
		${CPP_LIST}
		plh_Hook_amd64_gcc.cpp
		)
endif()

include_directories(${PLH_INC_DIR})

add_library(
	protolesshooks
	${H_LIST}
	${CPP_LIST}
	${ASM_LIST}
	)

install(
	FILES ${PLH_INC_DIR}/protolesshooks.h
	DESTINATION ${PLH_INSTALL_INC_SUBDIR}
	)

install(
	TARGETS protolesshooks
	DESTINATION ${PLH_INSTALL_LIB_SUBDIR}
	)

#...............................................................................
