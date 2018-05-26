function(cjailtest testname)
    add_executable(${testname} "${testname}.c")
    target_link_libraries(${testname} ${CHECK_LIBRARIES} libcjail)
    add_test(${testname} "${CMAKE_CURRENT_BINARY_DIR}/${testname}")
endfunction(cjailtest)

include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_SOURCE_DIR}/src")
include_directories(${CHECK_INCLUDE_DIRS})

cjailtest(test_utils)
cjailtest(basic_test)
cjailtest(timing_test)

add_executable(cjail_static_test cjail_static_test.c seccomptest.c)
target_link_libraries(cjail_static_test libcjail)
