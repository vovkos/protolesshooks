#...............................................................................

# .asm files are not compiled directly; add them just for convenient editing in IDE

set(
	SRC_LIST
	${PLH_INC_DIR}/protolesshooks.h
	)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	if(WIN32)
		set(
			SRC_LIST
			${SRC_LIST}
			thunk_amd64_msc.asm
			thunk_amd64_msc.cpp
			)
	else()
		set(
			SRC_LIST
			${SRC_LIST}
			thunk_amd64_gcc.asm
			thunk_amd64_gcc.cpp
			)
	endif()
else()
	if(WIN32)
		set(
			SRC_LIST
			${SRC_LIST}
			thunk_x86.asm
			thunk_x86_msc.cpp
			)
	else()
		set(
			SRC_LIST
			${SRC_LIST}
			thunk_x86.asm
			thunk_x86_gcc.cpp
			)
	endif()
endif()

include_directories(${PLH_INC_DIR})

add_library(
	protolesshooks
	${SRC_LIST}
	)

#...............................................................................
