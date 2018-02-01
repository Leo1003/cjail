cmake_minimum_required(VERSION 2.6)

set(LIB_SOURCE child_init.c cjail.c setup.c utils.c)
add_library(libcjail SHARED ${LIB_SOURCE})
set_target_properties(libcjail PROPERTIES OUTPUT_NAME "cjail" PREFIX "lib" VERSION ${VERSION} SOVERSION ${SOVERSION})

install(TARGETS libcjail LIBRARY DESTINATION lib)
