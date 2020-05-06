#...............................................................................

include_directories(${PLH_INC_DIR})

add_executable (
	test_main
	main.cpp
	)

target_link_libraries (
	test_main
	protolesshooks
	)

add_test(
	NAME test_main
	COMMAND test_main
	)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

if(WIN32)
	add_executable (
		test_seh
		seh.cpp
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
