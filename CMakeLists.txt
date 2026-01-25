cmake_minimum_required(VERSION 3.15)
project(XrdOfsOpenVerify)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(XRootD CONFIG REQUIRED)

add_library(XrdOfsOpenVerify SHARED
    src/XrdOfsOpenVerifyFile.cc
    src/XrdOfsOpenVerifyFileSystem.cc
    src/OpenVerifyCache.cpp
)

target_include_directories(XrdOfsOpenVerify
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(XrdOfsOpenVerify
    PRIVATE
        XRootD::XrdServer
        XRootD::XrdUtils
)

set_target_properties(XrdOfsOpenVerify PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "XrdOfsOpenVerify"
)

install(TARGETS XrdOfsOpenVerify
    LIBRARY DESTINATION lib64
)

enable_testing()

add_executable(openverify_cache_tests
    tests/OpenVerifyCacheTests.cc
    src/OpenVerifyCache.cpp
)

target_include_directories(openverify_cache_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_test(NAME openverify_cache_tests COMMAND openverify_cache_tests)
