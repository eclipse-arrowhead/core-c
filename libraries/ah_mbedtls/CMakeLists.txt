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

include(FindMbedTLS)
if (NOT mbedtls_FOUND)
    message(FATAL_ERROR "The MbedTLS library could not be found. Required.")
endif ()

add_library(ah_mbedtls STATIC ${SOURCE_FILES})
target_include_directories(ah_mbedtls
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_mbedtls PRIVATE ah_base MbedTLS::mbedtls)

set(
    TEST_FILES
    test/main.c
)

add_executable(ah_mbedtls_tests ${TEST_FILES})
target_link_libraries(ah_mbedtls_tests PRIVATE ah_base ah_mbedtls ah_unit)
