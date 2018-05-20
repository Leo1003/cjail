include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories("${CMAKE_SOURCE_DIR}/src")
include_directories(${CHECK_INCLUDE_DIRS})

add_executable(test_utils test_utils.c)
target_link_libraries(test_utils ${CHECK_LIBRARIES} libcjail)
add_test(test_utils "${CMAKE_CURRENT_BINARY_DIR}/test_utils")

add_executable(basic_test basic_test.c)
target_link_libraries(basic_test ${CHECK_LIBRARIES} libcjail)
add_test(basic_test "${CMAKE_CURRENT_BINARY_DIR}/basic_test")

add_executable(cjail_static_test cjail_static_test.c seccomptest.c)
target_link_libraries(cjail_static_test libcjail)
