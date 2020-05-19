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

#...............................................................................
