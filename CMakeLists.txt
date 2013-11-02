cmake_minimum_required(VERSION 2.8)
project(libkrypto)

if (NOT BUILD_IN_METTANODE)
    include(cmake/setup.cmake)
    include_directories(3rdparty/endian 3rdparty/support/include 3rdparty/plist/include)
endif()

include_directories(include)
add_subdirectory(lib)

# Build libsupport in standalone version.
if (NOT BUILD_IN_METTANODE)
    add_subdirectory(3rdparty/support/lib 3rdparty/plist)
endif()

if (BUILD_TESTING)
    add_subdirectory(tests)
endif (BUILD_TESTING)
