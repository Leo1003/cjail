cmake_minimum_required(VERSION 2.6)

set(LIB_SOURCE child_init.c child_init.h cjail.c setup.c setup.h utils.c utils.h)
add_library(libcjail SHARED ${LIB_SOURCE})
set_target_properties(libcjail PROPERTIES OUTPUT_NAME "cjail" PREFIX "lib" VERSION ${VERSION} SOVERSION ${SOVERSION})

install(TARGETS libcjail LIBRARY DESTINATION lib)
