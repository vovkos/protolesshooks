#...............................................................................

project(protolesshooks)
cmake_minimum_required(VERSION 3.3)
enable_testing()

set(PLH_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(PLH_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	set(TARGET_CPU CACHE STRING "Target CPU for cross-compilation")

	set_property(
		CACHE TARGET_CPU
		PROPERTY STRINGS
		""
		"amd64"
		"x86"
		)

	if("${TARGET_CPU}" STREQUAL "")
		# no need to adjust anything
	elseif("${TARGET_CPU}" STREQUAL "amd64")
		set(CMAKE_SIZEOF_VOID_P 8)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -mcx16")
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -m64 -mcx16")

		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS FALSE)
	elseif("${TARGET_CPU}" STREQUAL "x86")
		set(CMAKE_SIZEOF_VOID_P 4)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -m32")

		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS FALSE)
		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)
	else()
		message(FATAL_ERROR "Unsupported CPU: ${TARGET_CPU}")
	endif()
endif()

add_subdirectory(src)
add_subdirectory(samples)
add_subdirectory(test)

#...............................................................................
