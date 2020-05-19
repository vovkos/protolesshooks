#...............................................................................

include_directories(${PLH_INC_DIR})

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

add_executable (
	sample_00_trivial
	sample_00_trivial.cpp
	)

target_link_libraries (
	sample_00_trivial
	protolesshooks
	)

if (UNIX)
	target_link_libraries (
		sample_00_trivial
		pthread
		dl
		)
endif()

add_test(
	NAME sample_00_trivial
	COMMAND sample_00_trivial
	)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

add_executable (
	sample_01_params
	sample_01_params.cpp
	)

target_link_libraries (
	sample_01_params
	protolesshooks
	)

if (UNIX)
	target_link_libraries (
		sample_01_params
		pthread
		dl
		)
endif()

add_test(
	NAME sample_01_params
	COMMAND sample_01_params
	)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

add_executable (
	sample_02_enum
	sample_02_enum.cpp
)

target_link_libraries (
	sample_02_enum
	protolesshooks
)

if (UNIX)
	target_link_libraries (
		sample_02_enum
		pthread
		dl
	)
endif()

add_test(
	NAME sample_02_enum
	COMMAND sample_02_enum
)

# . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .

add_executable (
	sample_03_global
	sample_03_global.cpp
)

target_link_libraries (
	sample_03_global
	protolesshooks
)

if (UNIX)
	target_link_libraries (
		sample_03_global
		pthread
		dl
	)
endif()

add_test(
	NAME sample_03_global
	COMMAND sample_03_global
)

#...............................................................................
