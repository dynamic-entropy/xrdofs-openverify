cmake_minimum_required(VERSION 3.15)
project(XrdOfsOpenVerify LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

find_package(XRootD CONFIG REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)

add_library(XrdOfsOpenVerify SHARED
    src/XrdOfsOpenVerifyFile.cc
    src/XrdOfsOpenVerifyFileSystem.cc
    src/OpenVerifyCache.cpp
    src/OpenVerifyUrl.cc
    src/OpenVerifyHostReliability.cc
    src/OpenVerifyMetrics.cc
    src/OpenVerifySingleFlight.cc
    src/XrdOfsOpenVerifyImpl.cc
    src/OpenVerifyRucio.cc
    src/OpenVerifyRucioSelector.cc
)

target_include_directories(XrdOfsOpenVerify
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(XrdOfsOpenVerify
    PRIVATE
        XRootD::XrdServer
        XRootD::XrdUtils
        XRootD::XrdCl
        CURL::libcurl
        nlohmann_json::nlohmann_json
)

set_target_properties(XrdOfsOpenVerify PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "XrdOfsOpenVerify"
)

install(TARGETS XrdOfsOpenVerify
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
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

add_executable(openverify_singleflight_tests
    tests/OpenVerifySingleFlightTests.cc
    src/OpenVerifySingleFlight.cc
    src/OpenVerifyMetrics.cc
    src/OpenVerifyHostReliability.cc
)

target_include_directories(openverify_singleflight_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(openverify_singleflight_tests
    PRIVATE
        XRootD::XrdCl
)

add_test(NAME openverify_singleflight_tests COMMAND openverify_singleflight_tests)

add_executable(openverify_rucio_tests
    tests/OpenVerifyRucioTests.cc
    src/OpenVerifyRucio.cc
    src/OpenVerifyRucioSelector.cc
)

target_include_directories(openverify_rucio_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(openverify_rucio_tests
    PRIVATE
        CURL::libcurl
        nlohmann_json::nlohmann_json
        XRootD::XrdUtils
)

add_test(NAME openverify_rucio_tests COMMAND openverify_rucio_tests)

add_executable(openverify_url_tests
    tests/OpenVerifyUrlTests.cc
    src/OpenVerifyUrl.cc
)

target_include_directories(openverify_url_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_test(NAME openverify_url_tests COMMAND openverify_url_tests)

add_executable(openverify_static_fallback_tests
    tests/OpenVerifyStaticFallbackTests.cc
)

target_include_directories(openverify_static_fallback_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_test(NAME openverify_static_fallback_tests COMMAND openverify_static_fallback_tests)

add_executable(openverify_tried_tests
    tests/OpenVerifyTriedTests.cc
)

target_include_directories(openverify_tried_tests
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_test(NAME openverify_tried_tests COMMAND openverify_tried_tests)
