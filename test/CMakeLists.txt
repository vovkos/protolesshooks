#...............................................................................

include_directories(${PLH_INC_DIR})

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

add_executable (
	test_main
	test_main.cpp
	)

target_link_libraries (
	test_main
	protolesshooks
	)

if (UNIX)
	target_link_libraries (
		test_main
		pthread
		dl
		)
endif()

add_test(
	NAME test_main
	COMMAND test_main
	)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

if (CMAKE_SIZEOF_VOID_P EQUAL 4) # stdcall is x86-specific
	add_executable (
		test_stdcall
		test_stdcall.cpp
		)

	target_link_libraries (
		test_stdcall
		protolesshooks
		)

	if (UNIX)
		target_link_libraries (
			test_stdcall
			pthread
			dl
			)
	endif()

	add_test(
		NAME test_stdcall
		COMMAND test_stdcall
		)
endif()

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

if(WIN32)
	add_executable (
		test_seh
		test_seh.cpp
		)

	target_link_libraries (
		test_seh
		protolesshooks
		)

	add_test(
		NAME test_seh
		COMMAND test_seh
		)
endif()

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

if (WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 4) # thiscall and fastcall are msc-x86-specific
	add_executable (
		test_thiscall
		test_thiscall.cpp
		)

	target_link_libraries (
		test_thiscall
		protolesshooks
		)

	add_test(
		NAME test_thiscall
		COMMAND test_thiscall
		)

	add_executable (
		test_fastcall
		test_fastcall.cpp
		)

	target_link_libraries (
		test_fastcall
		protolesshooks
		)

	add_test(
		NAME test_fastcall
		COMMAND test_fastcall
		)
endif()

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

if (GCC AND CMAKE_SIZEOF_VOID_P EQUAL 4) # regparm attrs are gcc-x86-specific
	add_executable (
		test_regparm
		test_regparm.cpp
		)

	target_link_libraries (
		test_regparm
		protolesshooks
		pthread
		dl
		)

	add_test(
		NAME test_regparm
		COMMAND test_regparm
		)
endif()

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
