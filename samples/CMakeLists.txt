#...............................................................................

include_directories(${PLH_INC_DIR})

add_executable (
	sample_trivial
	trivial.cpp
	)

target_link_libraries (
	sample_trivial
	protolesshooks
	)

if (UNIX)
	target_link_libraries (
		sample_trivial
		pthread
		dl
		)
endif()

add_test(
	NAME sample_trivial
	COMMAND sample_trivial
	)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

add_executable (
	sample_params
	params.cpp
	)

target_link_libraries (
	sample_params
	protolesshooks
	)

if (UNIX)
	target_link_libraries (
		sample_params
		pthread
		dl
		)
endif()

add_test(
	NAME sample_params
	COMMAND sample_params
	)

#...............................................................................
