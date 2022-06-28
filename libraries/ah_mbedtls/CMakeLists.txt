cmake_minimum_required(VERSION 3.15)
project(ah_mbedtls C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/internal/_mbedtls.h
    include/ah/mbedtls.h
    src/mbedtls-client.c
    src/mbedtls-client.h
    src/mbedtls-server.c
    src/mbedtls-server.h
    src/mbedtls-utils.c
    src/mbedtls-utils.h
)

add_library(ah_mbedtls STATIC ${SOURCE_FILES})
target_include_directories(ah_mbedtls PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

include(FindMbedTLS)
if (mbedtls_FOUND)
    target_link_libraries(ah_mbedtls PUBLIC ah_base MbedTLS::mbedtls)
else ()
    message(FATAL_ERROR "Could not find or download MbedTLS, which is required to build this library.")
endif ()

set(
    TEST_FILES
    test/certs.c
    test/certs.h
    test/main.c
    test/test-mbedtls.c
)

add_executable(ah_mbedtls_tests ${TEST_FILES})
target_link_libraries(ah_mbedtls_tests PRIVATE ah_mbedtls ah_unit)
