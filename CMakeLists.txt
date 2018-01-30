cmake_minimum_required(VERSION 2.6)
project(cjail)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(libseccomp REQUIRED)
