#--------------------------------
# Setup targets & properties
#
add_library(libcjail SHARED
    cgroup.c
    cleanup.c
    cjail.c
    fds.c
    filesystem.c
    init.c
    logger.c
    process.c
    scconfig_parser.c
    simple_seccomp.c
    sigset.c
    taskstats.c
    trace.c
    utils.c
)
add_library(CJail::libcjail ALIAS libcjail)

target_include_directories(libcjail
    INTERFACE
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${LIBSECCOMP_INCLUDE_DIRS}
)
target_link_libraries(libcjail
    PRIVATE
        libseccomp::libseccomp
        "bsd"
)
set_target_properties(libcjail PROPERTIES
    OUTPUT_NAME "cjail"
    PREFIX "lib"
    VERSION ${PROJECT_VERSION} SOVERSION ${SOVERSION}
    PUBLIC_HEADER
        "${CMAKE_SOURCE_DIR}/include/cjail.h;
        ${CMAKE_SOURCE_DIR}/include/scconfig.h"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

#--------------------------------
# Installation
#
install(TARGETS libcjail
    EXPORT cjail_targets
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
