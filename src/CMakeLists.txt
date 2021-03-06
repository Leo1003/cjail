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
    loop.c
    mount.c
    process.c
    protocol.c
    scconfig_parser.c
    simple_seccomp.c
    sigset.c
    taskstats.c
    taskstats_pool.c
    trace.c
    utils.c
)
add_library(CJail::libcjail ALIAS libcjail)

set(PUBLIC_HEADERS
    ${CMAKE_SOURCE_DIR}/include/cjail.h
    ${CMAKE_SOURCE_DIR}/include/scconfig.h
    ${CMAKE_SOURCE_DIR}/include/filesystem.h
)

target_include_directories(libcjail
    PUBLIC
        $<INSTALL_INTERFACE:include/cjail>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/include
)
target_link_libraries(libcjail
    PRIVATE
        libseccomp::libseccomp
        libnl::libnl
        libnl::genl
        "bsd"
)
set_target_properties(libcjail PROPERTIES
    OUTPUT_NAME "cjail"
    PREFIX "lib"
    VERSION ${PROJECT_VERSION} SOVERSION ${SOVERSION}
    PUBLIC_HEADER "${PUBLIC_HEADER_LIST}"
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
