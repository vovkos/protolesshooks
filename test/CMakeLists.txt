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

#...............................................................................
