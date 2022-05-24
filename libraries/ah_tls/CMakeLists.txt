cmake_minimum_required(VERSION 3.15)
project(ah_tls C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/tls.h
    include/ah/internal/_tls.h
)

set(
    LINKED_LIBRARIES
    ah_base
)

include(FindMbedTLS)

if (mbedtls_FOUND)
    list(APPEND SOURCE_FILES src/tls-mbedtls.c)
    list(APPEND LINKED_LIBRARIES MbedTLS::mbedtls)
else ()
    message(FATAL_ERROR "No supported TLS/SSL library available (`MbedTLS`). Required.")
endif ()

add_library(ah_tls STATIC ${SOURCE_FILES})
target_include_directories(ah_tls
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_tls PRIVATE ah_base ${LINKED_LIBRARIES})

set(
    TEST_FILES
    test/main.c
)

add_executable(ah_tls_tests ${TEST_FILES})
target_link_libraries(ah_tls_tests PRIVATE ah_base ah_tls ah_unit)
