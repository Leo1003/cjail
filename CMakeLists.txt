#--------------------------------
# Project configuration
#
cmake_minimum_required(VERSION 3.0.2)
project(cjail VERSION 0.7.2 LANGUAGES C)
set(SOVERSION 0)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "build type not set, default to release")
    set(CMAKE_BUILD_TYPE Release)
endif()

message("Build Type: ${CMAKE_BUILD_TYPE}")

#--------------------------------
# Building targets
#
find_package(libseccomp REQUIRED)

include(GNUInstallDirs)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -Wall")

set(CFG_CGROOT CACHE PATH "Path to your system's cgroup mounting directory")
set(CFG_CGNAME CACHE STRING "Format string for creating cgroup's name. This should contain a %d entry to indicate the pid of the sandbox")
set(CFG_UTSNAME CACHE STRING "The host name in the UTS namespace")
set(CFG_INITNAME CACHE STRING "The string to replace the argv of the in-box init process")
set(CFG_PROCNAME CACHE STRING "The process name of the in-box init process")

configure_file(${CMAKE_SOURCE_DIR}/src/config.h.in ${CMAKE_BINARY_DIR}/include/config.h @ONLY)

add_subdirectory(src)
add_subdirectory(tools)

#--------------------------------
# Tests configuration
#
find_package(Criterion)

if(CRITERION_FOUND)
    message(STATUS "Found Criterion library")
    message(STATUS "Test Enabled")
    enable_testing()
    add_subdirectory(test)
else()
    message(WARNING "Criterion library not found!\nTests disabled")
endif()

#--------------------------------
# Exporting
#
set(CMAKE_CONFIG_DIR "share/cmake/Modules")

install(
    EXPORT cjail_targets
    FILE CJailTargets.cmake
    NAMESPACE CJail::
    DESTINATION ${CMAKE_CONFIG_DIR}
)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/CJailConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CJailConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CJailConfig.cmake
    INSTALL_DESTINATION ${CMAKE_CONFIG_DIR}
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Findlibseccomp.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/CJailConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/CJailConfigVersion.cmake
    DESTINATION ${CMAKE_CONFIG_DIR}
)

export(
    EXPORT cjail_targets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/CJailTargets.cmake
    NAMESPACE CJail::
)

export(PACKAGE CJail)
