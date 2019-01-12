# This file is licensed under the WTFPL version 2 -- you can see the full
# license over at http://www.wtfpl.net/txt/copying/
#
# - Try to find Criterion
#
# Once done this will define
#  CRITERION_FOUND - System has Criterion
#  CRITERION_INCLUDE_DIRS - The Criterion include directories
#  CRITERION_LIBRARIES - The libraries needed to use Criterion
#  CRITERION_VERSION - The version of Criterion
#
# and the following imported target:
#   Criterion::Criterion - The Criterion framework

find_package(PkgConfig)
pkg_check_modules(PC_CRITERION criterion)

find_path(CRITERION_INCLUDE_DIRS
    NAMES criterion/criterion.h
    HINTS ${PC_CRITERION_INCLUDE_DIRS}
        ${PC_CRITERION_INCLUDEDIR}
    PATH_SUFFIXES criterion
)

find_library(CRITERION_LIBRARIES
    NAMES criterion libcriterion
    HINTS ${PC_CRITERION_LIBRARY_DIRS}
        ${PC_CRITERION_LIBDIR}
)

set(CRITERION_VERSION ${PC_CRITERION_VERSION})

include(FindPackageHandleStandardArgs)
# handle the QUIET and REQUIRED arguments and set CRITERION_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Criterion
    FOUND_VAR CRITERION_FOUND
    REQUIRED_VARS CRITERION_LIBRARIES CRITERION_INCLUDE_DIRS
    VERSION_VAR LIBSECCOMP_VERSION
)

if(CRITERION_FOUND AND NOT TARGET Criterion::Criterion)
    add_library(Criterion::Criterion INTERFACE IMPORTED)
    set_target_properties(Criterion::Criterion PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES   ${CRITERION_INCLUDE_DIRS}
        INTERFACE_LINK_LIBRARIES        ${CRITERION_LIBRARIES}
    )
endif()
