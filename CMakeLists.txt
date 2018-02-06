cmake_minimum_required(VERSION 2.6)
project(cjail)
set(VERSION 0.1)
set(SOVERSION 0)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

if(NOT CMAKE_BUILD_TYPE)
MESSAGE(STATUS "build type not set, default to release")
set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

message("Build Type: ${CMAKE_BUILD_TYPE}")

find_package(libseccomp REQUIRED)

include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories(${LIBSECCOMP_INCLUDE_DIRS})
add_subdirectory(src)
enable_testing()
add_subdirectory(test)
