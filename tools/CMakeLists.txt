#--------------------------------
# Setup targets & properties
#
add_executable(cjail main.c statistics.c)
add_executable(CJail::cjail ALIAS cjail)

set_target_properties(cjail PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
target_link_libraries(cjail
    PRIVATE
        CJail::libcjail
        "m"
        "bsd"
)

#--------------------------------
# Installation
#
install(TARGETS cjail
    EXPORT cjail_targets
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
