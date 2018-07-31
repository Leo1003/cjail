cmake_minimum_required(VERSION 3.0.2)
project(cjail C)
set(VERSION 0.6.0)
set(SOVERSION 2)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(GNUInstallDirs)

if(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "build type not set, default to release")
    set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

message("Build Type: ${CMAKE_BUILD_TYPE}")

find_package(libseccomp REQUIRED)
find_package(Check)

# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
# set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

add_subdirectory(src)
add_subdirectory(tools)

if(CHECK_FOUND)
    message(STATUS "Found Check library.")
    message(STATUS "Test Enabled.")
    enable_testing()
    add_subdirectory(test)
else(CHECK_FOUND)
    message(WARNING "Check library not found!\nTests disabled.")
endif(CHECK_FOUND)
