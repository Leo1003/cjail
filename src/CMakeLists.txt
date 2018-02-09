cmake_minimum_required(VERSION 2.6)

set(LIBCJAIL_SOURCE cgroup.c child_init.c cjail.c setup.c taskstats.c utils.c)
add_library(libcjail SHARED ${LIBCJAIL_SOURCE})
target_link_libraries(libcjail ${LIBSECCOMP_LIBRARIES} "bsd")
set_target_properties(libcjail PROPERTIES OUTPUT_NAME "cjail" PREFIX "lib" VERSION ${VERSION} SOVERSION ${SOVERSION})

install(TARGETS libcjail LIBRARY DESTINATION lib)
