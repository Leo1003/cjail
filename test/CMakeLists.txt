function(cjailtest testname)
    add_executable(${testname} "${testname}.c")
    target_link_libraries(${testname} check::check libcjail)
    target_include_directories(${testname}
            PRIVATE "${CMAKE_SOURCE_DIR}/src"
            PRIVATE "${CHECK_INCLUDE_DIRS}"
    )
    add_test(${testname} "${CMAKE_CURRENT_BINARY_DIR}/${testname}")
endfunction(cjailtest)

cjailtest(test_utils)
cjailtest(basic_test)
cjailtest(timing_test)

add_executable(cjail_static_test cjail_static_test.c seccomptest.c)
target_include_directories(cjail_static_test
        PRIVATE "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(cjail_static_test libcjail)
