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
    include(FetchContent)
    FetchContent_Declare(
        MbedTLS
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG d65aeb37349ad1a50e0f6c9b694d4b5290d60e49 # v3.1.0
    )
    FetchContent_MakeAvailable(MbedTLS)
    target_link_libraries(ah_mbedtls PUBLIC ah_base MbedTLS)
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
