#--------------------------------
# Function Defination
#
function(cjailtest testname)
    add_executable(${testname} "${testname}.c")
    target_link_libraries(${testname}
        PRIVATE
            ${CRITERION_LIBRARY}
            CJail::libcjail
    )
    target_include_directories(${testname}
        PRIVATE
            ${CRITERION_INCLUDE_DIR}
            "${CMAKE_SOURCE_DIR}/src"
            ${CMAKE_BINARY_DIR}/include
    )
    add_test(${testname} "${CMAKE_CURRENT_BINARY_DIR}/${testname}")
endfunction(cjailtest)

#--------------------------------
# Setup tests
#
cjailtest(utils_test)
cjailtest(basic_test)
cjailtest(timing_test)
cjailtest(scconfig_parser_test)

#--------------------------------
# Setup static_test
# (for temporary usage, will be removed in future)
#
add_executable(cjail_static_test cjail_static_test.c seccomptest.c)
target_link_libraries(cjail_static_test
    PRIVATE
        CJail::libcjail
)
