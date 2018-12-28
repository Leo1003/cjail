#--------------------------------
# Function Defination
#
set(ASSETS_DIR "${CMAKE_SOURCE_DIR}/assets")

function(cjailtest testname)
    add_executable(${testname} "${testname}.c")
    target_link_libraries(${testname}
        PRIVATE
            ${CRITERION_LIBRARY}
            CJail::libcjail
    )
    target_include_directories(${testname}
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CRITERION_INCLUDE_DIR}
            "${CMAKE_SOURCE_DIR}/src"
            ${CMAKE_BINARY_DIR}/include
    )
    add_test(${testname} "${CMAKE_CURRENT_BINARY_DIR}/${testname}")
endfunction(cjailtest)

function(find_assets VAR NAMES)
    find_file(${VAR}
        NAMES ${NAMES}
        PATHS "${ASSETS_DIR}"
        NO_DEFAULT_PATH
        NO_PACKAGE_ROOT_PATH
        NO_SYSTEM_ENVIRONMENT_PATH
        NO_CMAKE_SYSTEM_PATH
    )
endfunction(find_assets)

find_assets(DISKIMAGE1_PATH image1.img)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/assets.h.in ${CMAKE_CURRENT_BINARY_DIR}/assets.h @ONLY)

#--------------------------------
# Setup tests
#
cjailtest(utils_test)
cjailtest(basic_test)
cjailtest(timing_test)
cjailtest(scconfig_parser_test)
cjailtest(mount_test)

#--------------------------------
# Setup static_test
# (for temporary usage, will be removed in future)
#
add_executable(cjail_static_test cjail_static_test.c seccomptest.c)
target_link_libraries(cjail_static_test
    PRIVATE
        CJail::libcjail
)
