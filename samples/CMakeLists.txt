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

add_test(
	NAME sample_params
	COMMAND sample_params
	)

#...............................................................................
