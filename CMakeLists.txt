cmake_minimum_required(VERSION 2.8)
project(libkrypto)

if (NOT BUILD_IN_UVVY)
    include(cmake/setup.cmake)
    include_directories(3rdparty/endian 3rdparty/arsenal/include)
endif()

include_directories(include)

include_directories(../3rdparty) # for sodiumpp/sodiumpp.h
add_subdirectory(lib)

# Build libarsenal in standalone version.
if (NOT BUILD_IN_UVVY)
    add_subdirectory(3rdparty/arsenal/lib)
endif()

if (BUILD_TESTING)
    add_subdirectory(tests)
endif (BUILD_TESTING)
