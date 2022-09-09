cmake_minimum_required(VERSION 3.15)
project(
    ah_mbedtls
    LANGUAGES C
    VERSION 1.0.0
)
set(CMAKE_C_STANDARD 99)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Try to find a local installation of MbedTLS.
include(FindMbedTLS)
if (NOT MbedTLS_FOUND)
    # If no such is available, download, install and then find the downloaded MBedTLS version.
    include(DownloadMbedTLS)
endif ()

set(
    SOURCE_FILES
    include/ah/internal/_mbedtls.h
    include/ah/mbedtls.h
    src/mbedtls-client.c
    src/mbedtls-client.h
    src/mbedtls-lib-version.c
    src/mbedtls-server.c
    src/mbedtls-server.h
    src/mbedtls-utils.c
    src/mbedtls-utils.h
)

add_library(ah_mbedtls STATIC ${SOURCE_FILES})
target_include_directories(
    ah_mbedtls
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)
target_link_libraries(ah_mbedtls PUBLIC ah_base MbedTLS::mbedtls)

file(
    GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/ah_i_mbedtls_lib_version.h
    CONTENT "\
#define AH_I_MBEDTLS_LIB_VERSION_STR \"${PROJECT_VERSION}\";\r\n\
#define AH_I_MBEDTLS_LIB_VERSION_MAJOR ${PROJECT_VERSION_MAJOR}u;\r\n\
#define AH_I_MBEDTLS_LIB_VERSION_MINOR ${PROJECT_VERSION_MINOR}u;\r\n\
#define AH_I_MBEDTLS_LIB_VERSION_PATCH ${PROJECT_VERSION_PATCH}u;\r\n"
    TARGET ah_mbedtls
)

set(
    TEST_FILES
    test/certs.c
    test/certs.h
    test/main.c
    test/test-mbedtls.c
)

add_executable(ah_mbedtls_tests ${TEST_FILES})
target_link_libraries(ah_mbedtls_tests PRIVATE ah_mbedtls ah_unit)
