#...............................................................................

# .asm files are not compiled directly; add them just for convenient editing in IDE

set(
	SRC_LIST
	${PLH_INC_DIR}/protolesshooks.h
	plh_HookMgr.h
	plh_HookMgr.cpp
	)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(
		SRC_LIST
		${SRC_LIST}
		plh_Hook_x86.cpp
		thunk_x86.asm
		)
elseif(WIN32)
	set(
		SRC_LIST
		${SRC_LIST}
		plh_Hook_amd64_msc.cpp
		thunk_amd64_msc.asm
		)
else()
	set(
		SRC_LIST
		${SRC_LIST}
		plh_Hook_amd64_gcc.cpp
		thunk_amd64_gcc.asm
		)
endif()

include_directories(${PLH_INC_DIR})

add_library(
	protolesshooks
	${SRC_LIST}
	)

#...............................................................................
