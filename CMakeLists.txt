#...............................................................................

project(protolesshooks)
cmake_minimum_required(VERSION 3.3)
enable_testing()

set(PLH_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(PLH_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_subdirectory(src)
add_subdirectory(samples)
add_subdirectory(test)

#...............................................................................
