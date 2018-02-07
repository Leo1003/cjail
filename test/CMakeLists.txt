include_directories("${CMAKE_SOURCE_DIR}/include")
include_directories(${CHECK_INCLUDE_DIR})
add_executable(test_utils test_utils.c)
target_link_libraries(test_utils ${CHECK_LIBRARIES} libcjail)

add_test(test_utils "${CMAKE_CURRENT_BINARY_DIR}/test_utils")
