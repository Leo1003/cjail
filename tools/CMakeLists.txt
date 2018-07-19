add_executable(cjail main.c)
target_include_directories(cjail
        PRIVATE "${CMAKE_SOURCE_DIR}/include"
)
set_target_properties(cjail PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
target_link_libraries(cjail libcjail "m")

install(TARGETS cjail
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
