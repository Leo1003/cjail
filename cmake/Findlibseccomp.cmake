# Original work Copyright (c) 2013, Intel Corporation
# Modified work Copyright (c) 2018, Leo Chen
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
# Try to find libseccomp include and library directories.
#
# After successful discovery, these variables will be set:
#   LIBSECCOMP_FOUND - system has libseccomp with correct version
#   LIBSECCOMP_INCLUDE_DIRS - containg the libseccomp headers
#   LIBSECCOMP_LIBRARIES - containg the libseccomp library
#   LIBSECCOMP_VERSION - the version string of libseccomp
#
# and the following imported target:
#   libseccomp::libseccomp - The libseccomp library

find_package(PkgConfig)
pkg_check_modules(PC_LIBSECCOMP libseccomp)

find_path(LIBSECCOMP_INCLUDE_DIRS
    NAMES seccomp.h
    HINTS ${PC_LIBSECCOMP_INCLUDE_DIRS}
        ${PC_LIBSECCOMP_INCLUDEDIR}
)

find_library(LIBSECCOMP_LIBRARIES
    NAMES seccomp
    HINTS ${PC_LIBSECCOMP_LIBRARY_DIRS}
        ${PC_LIBSECCOMP_LIBDIR}
)

set(LIBSECCOMP_VERSION ${PC_LIBSECCOMP_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libseccomp
    FOUND_VAR LIBSECCOMP_FOUND
    REQUIRED_VARS LIBSECCOMP_INCLUDE_DIRS LIBSECCOMP_LIBRARIES
    VERSION_VAR LIBSECCOMP_VERSION
)

if(LIBSECCOMP_FOUND AND NOT TARGET libseccomp::libseccomp)
    add_library(libseccomp::libseccomp INTERFACE IMPORTED)
    set_target_properties(libseccomp::libseccomp PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES   "${LIBSECCOMP_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES        "${LIBSECCOMP_LIBRARIES}"
    )
endif()

mark_as_advanced(LIBSECCOMP_LIBRARIES LIBSECCOMP_INCLUDE_DIRS)
