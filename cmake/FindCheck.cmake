# Copyright (c) 2018, Leo Chen
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name of Intel Corporation nor the names of its contributors may
#   be used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Try to find check include and library directories.
#
# After successful discovery, these variables will be set:
#   CHECK_FOUND - system has check with correct version
#   CHECK_INCLUDE_DIRS - containg the check headers
#   CHECK_LIBRARIES - containg the check library
#   CHECK_VERSION - the version string of check
#
# and the following imported target:
#   check::check - The check library

find_package(PkgConfig)
pkg_check_modules(PC_CHECK check)

find_path(CHECK_INCLUDE_DIRS
    NAMES check.h
    HINTS ${PC_CHECK_INCLUDE_DIRS}
        ${PC_CHECK_INCLUDEDIR}
)

find_library(CHECK_LIBRARIES
    NAMES check
    HINTS ${PC_CHECK_LIBRARY_DIRS}
        ${PC_CHECK_LIBDIR}
)

set(CHECK_VERSION ${PC_CHECK_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Check
    FOUND_VAR CHECK_FOUND
    REQUIRED_VARS CHECK_INCLUDE_DIRS CHECK_LIBRARIES
    VERSION_VAR CHECK_VERSION
)

if(CHECK_FOUND AND NOT TARGET check::check)
    add_library(check::check INTERFACE IMPORTED)
    set_target_properties(check::check PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES   "${CHECK_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES        "${CHECK_LIBRARIES}"
    )
endif()
