# Try to find libnl include and library directories.
#
# After successful discovery, these variables will be set:
#   LIBNL_FOUND - system has libnl with correct version
#   LIBNL_INCLUDE_DIRS - containg the libnl headers
#   LIBNL_LIBRARIES - containg the libnl libraries
#   LIBNL_VERSION - the version string of libnl
#
# and the following imported target:
#   libnl::libnl - The libnl core library
#
# and the following imported target may also be set:
#   libnl::cli - The libnl command line interface api extension
#   libnl::genl - The libnl generic netlink extension
#   libnl::idiag - The libnl inet diag extension
#   libnl::nf - The libnl netfilter extension
#   libnl::route - The libnl routing extension
#   libnl::xfrm - The libnl xfrm extension

set(LIBNL_COMPONENTS
    libnl
    cli
    genl
    idiag
    nf
    route
    xfrm
)
set(LIBNL_LIBNL_HEADER "netlink/version.h")
set(LIBNL_LIBNL_LIB "nl-3")
set(LIBNL_CLI_HEADER "netlink/cli/link.h")
set(LIBNL_CLI_LIB "nl-cli-3")
set(LIBNL_GENL_HEADER "netlink/genl/genl.h")
set(LIBNL_GENL_LIB "nl-genl-3")
set(LIBNL_IDIAG_HEADER "netlink/idiag/idiagnl.h")
set(LIBNL_IDIAG_LIB "nl-idiag-3")
set(LIBNL_NF_HEADER "netlink/netfilter/netfilter.h")
set(LIBNL_NF_LIB "nl-nf-3")
set(LIBNL_ROUTE_HEADER "netlink/route/route.h")
set(LIBNL_ROUTE_LIB "nl-route-3")
set(LIBNL_XFRM_HEADER "netlink/xfrm/template.h")
set(LIBNL_XFRM_LIB "nl-xfrm-3")

list(APPEND LIBNL_FIND_COMPONENTS libnl)
if(Libnl_FIND_COMPONENTS)
    foreach(_req_comp ${Libnl_FIND_COMPONENTS})
        list(FIND LIBNL_COMPONENTS "${_req_comp}" _comp_index)
        if(${_comp_index} EQUAL -1)
            message(FATAL_ERROR "Unknown components: ${_req_comp}")
        endif()
        list(APPEND LIBNL_FIND_COMPONENTS ${_req_comp})
    endforeach()
endif()
list(REMOVE_DUPLICATES LIBNL_FIND_COMPONENTS)

find_package(PkgConfig)
include(FindPackageHandleStandardArgs)

foreach(_comp ${LIBNL_FIND_COMPONENTS})
    string(TOUPPER "${_comp}" _up_comp)
    if(${_comp} STREQUAL libnl)
        pkg_check_modules(PC_LIBNL_${_up_comp} "libnl-3.0")
    else()
        pkg_check_modules(PC_LIBNL_${_up_comp} "libnl-${_comp}-3.0")
    endif()

    find_path(LIBNL_${_up_comp}_INCLUDE_DIRS
        NAMES ${LIBNL_${_up_comp}_HEADER}
        HINTS ${PC_LIBNL_${_up_comp}_INCLUDE_DIRS}
        PATH_SUFFIXES
            include/libnl3
            include
    )

    find_library(LIBNL_${_up_comp}_LIBRARIES
        NAMES ${LIBNL_${_up_comp}_LIB}
        HINTS ${PC_LIBNL_${_up_comp}_LIBRARY_DIRS}
    )

    set(LIBNL_${_up_comp}_VERSION ${PC_LIBNL_${_up_comp}_VERSION})
    if(NOT LIBNL_VERSION)
        set(LIBNL_VERSION ${LIBNL_${_up_comp}_VERSION})
    endif()

    find_package_handle_standard_args(Libnl_${_comp}
        FOUND_VAR LIBNL_${_up_comp}_FOUND
        REQUIRED_VARS LIBNL_${_up_comp}_INCLUDE_DIRS LIBNL_${_up_comp}_LIBRARIES
        VERSION_VAR LIBNL_${_up_comp}_VERSION
    )

    if(${LIBNL_${_up_comp}_FOUND})
        list(APPEND LIBNL_LIBRARIES "${LIBNL_${_up_comp}_LIBRARIES}")
        list(APPEND LIBNL_INCLUDE_DIRS "${LIBNL_${_up_comp}_INCLUDE_DIRS}")

        if(NOT TARGET libnl::${_comp})
            add_library(libnl::${_comp} INTERFACE IMPORTED)
            set_target_properties(libnl::${_comp} PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES   "${LIBNL_${_up_comp}_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES        "${LIBNL_${_up_comp}_LIBRARIES}"
            )
            if(NOT ${_comp} STREQUAL libnl)
                add_dependencies(libnl::${_comp} libnl::libnl)
            endif()
        endif()
        list(APPEND LIBNL_TARGETS "libnl::${_comp}")
    endif()

    mark_as_advanced(${LIBNL_${_up_comp}_LIBRARIES} ${LIBNL_${_up_comp}_INCLUDE_DIRS})
endforeach()

list(REMOVE_DUPLICATES LIBNL_LIBRARIES)
list(REMOVE_DUPLICATES LIBNL_INCLUDE_DIRS)
list(REMOVE_DUPLICATES LIBNL_TARGETS)

find_package_handle_standard_args(Libnl
    FOUND_VAR LIBNL_FOUND
    REQUIRED_VARS LIBNL_LIBRARIES LIBNL_INCLUDE_DIRS
    VERSION_VAR LIBNL_VERSION
    HANDLE_COMPONENTS
)

mark_as_advanced(LIBNL_LIBRARIES LIBNL_INCLUDE_DIRS)
