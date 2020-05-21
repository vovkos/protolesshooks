#...............................................................................

project(protolesshooks)
cmake_minimum_required(VERSION 3.3)

#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

include(version.cmake)

set(PLH_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(PLH_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(PLH_INSTALL_LIB_SUBDIR lib)

if(WIN32)
	set(PLH_INSTALL_INC_SUBDIR     include)
	set(PLH_INSTALL_LICENSE_SUBDIR license)
else()
	set(PLH_INSTALL_INC_SUBDIR     include/${PROJECT_NAME})
	set(PLH_INSTALL_LICENSE_SUBDIR share/${PROJECT_NAME}/license)
endif()

#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

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

		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS TRUE)
		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS FALSE)
	elseif("${TARGET_CPU}" STREQUAL "x86")
		set(CMAKE_SIZEOF_VOID_P 4)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")

		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS FALSE)
		set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB32_PATHS TRUE)
	else()
		message(FATAL_ERROR "Unsupported CPU: ${TARGET_CPU}")
	endif()

	set(_EXTRA_CXX_FLAGS
		-std=c++11
		-fvisibility=hidden
		-Wno-dangling-else
		-Wno-logical-op-parentheses
		)

	string(REPLACE ";" " " _EXTRA_CXX_FLAGS "${_EXTRA_CXX_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_EXTRA_CXX_FLAGS}")
endif()

#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

enable_testing()

add_subdirectory(src)
add_subdirectory(samples)
add_subdirectory(test)

#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

install(
	FILES LICENSE.txt
	DESTINATION ${PLH_INSTALL_LICENSE_SUBDIR}
	)

#...............................................................................

set(CPACK_PACKAGE_VERSION_MAJOR ${PLH_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PLH_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PLH_VERSION_PATCH})

if(APPLE)
	set(CPACK_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PLH_VERSION_FULL}-mac)
else()
	string(TOLOWER ${CMAKE_SYSTEM_NAME} OS_NAME)
	math(EXPR BITNESS "${CMAKE_SIZEOF_VOID_P} * 8")
	set(CPACK_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PLH_VERSION_FULL}-${OS_NAME}${BITNESS})
endif()

if(WIN32)
	set(CPACK_SOURCE_GENERATOR 7Z)
else()
	set(CPACK_SOURCE_GENERATOR TXZ)
endif()

set(CPACK_SOURCE_IGNORE_FILES "/[.];[.]user$;/build/;/ci/;/paths.cmake$")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PLH_VERSION_FULL}-src)

include(CPack)

#...............................................................................
