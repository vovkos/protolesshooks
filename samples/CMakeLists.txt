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

add_executable (
	sample_params
	params.cpp
	)

target_link_libraries (
	sample_params
	protolesshooks
	)

if(WIN32)
	add_executable (
		sample_seh
		seh.cpp
		)

	target_link_libraries (
		sample_seh
		protolesshooks
		)
endif()

#...............................................................................
