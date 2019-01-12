#--------------------------------
# Test Building Function Definitions
#
function(cjail_utest test)
    add_executable("unit_${test}" "unit/${test}.c")
    target_link_libraries("unit_${test}"
        PRIVATE
            ${CRITERION_LIBRARY}
            CJail::libcjail
    )
    target_include_directories("unit_${test}"
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CRITERION_INCLUDE_DIR}
            "${CMAKE_SOURCE_DIR}/src"
    )
    add_test("unit/${test}" "${CMAKE_CURRENT_BINARY_DIR}/unit_${test}")
endfunction(cjail_utest)

function(cjail_itest test)
    add_executable("integration_${test}" "integration/${test}.c")
    target_link_libraries("integration_${test}"
        PRIVATE
            ${CRITERION_LIBRARY}
            CJail::libcjail
    )
    target_include_directories("integration_${test}"
        PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CRITERION_INCLUDE_DIR}
    )
    add_test("integration/${test}" "${CMAKE_CURRENT_BINARY_DIR}/integration_${test}")
endfunction(cjail_itest)

#--------------------------------
# Find Testing Assets
#
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

set(ASSETS_DIR "${CMAKE_SOURCE_DIR}/assets")
find_assets(DISKIMAGE1_PATH image1.img)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/assets.h.in ${CMAKE_CURRENT_BINARY_DIR}/assets.h @ONLY)

#--------------------------------
# Setup tests
#
cjail_utest(utils)
cjail_utest(scconfig_parser)
cjail_utest(mount)

cjail_itest(basic)
cjail_itest(timing)
