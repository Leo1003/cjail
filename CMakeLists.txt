cmake_minimum_required(VERSION 2.6)
project(cjail)
set(VERSION 0.5.4)
set(SOVERSION 2)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

if(NOT CMAKE_BUILD_TYPE)
MESSAGE(STATUS "build type not set, default to release")
set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

message("Build Type: ${CMAKE_BUILD_TYPE}")

find_package(libseccomp REQUIRED)
find_package(Check)

include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories(${LIBSECCOMP_INCLUDE_DIRS})

add_subdirectory(src)
if(CHECK_FOUND)
    message(STATUS "Found Check library.")
    message(STATUS "Test Enabled.")
    enable_testing()
    add_subdirectory(test)
else(CHECK_FOUND)
    message(WARNING "Check library not found!\nTests disabled.")
endif(CHECK_FOUND)
