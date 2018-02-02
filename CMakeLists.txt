cmake_minimum_required(VERSION 2.6)
project(cjail)
set(VERSION 0.1)
set(SOVERSION 0)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(libseccomp REQUIRED)

message("Build Type: ${CMAKE_BUILD_TYPE}")

include_directories("${CMAKE_SOURCE_DIR}/include")
add_subdirectory(src)
