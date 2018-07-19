

add_library(libcjail SHARED
                cgroup.c
                cleanup.c
                cjail.c
                fds.c
                filesystem.c
                init.c
                logger.c
                process.c
                scmp.c
                sigset.c
                taskstats.c
                utils.c
)
target_include_directories(libcjail
        PRIVATE ${LIBSECCOMP_INCLUDE_DIRS}
)
target_link_libraries(libcjail ${LIBSECCOMP_LIBRARIES} "bsd")
set_target_properties(libcjail PROPERTIES OUTPUT_NAME "cjail" PREFIX "lib"
                                VERSION ${VERSION} SOVERSION ${SOVERSION}
                                PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/cjail.h"
                                LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

install(TARGETS libcjail
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
