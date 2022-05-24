cmake_minimum_required(VERSION 3.15)
project(ah_x509 C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/x509.h
    include/ah/internal/_x509.h
)

set(
    LINKED_LIBRARIES
    ah_base
)

include(FindMbedTLS)

if (mbedtls_FOUND)
    list(APPEND SOURCE_FILES src/x509-mbedtls.c)
    list(APPEND LINKED_LIBRARIES MbedTLS::mbedx509)
else ()
    message(FATAL_ERROR "No supported X.509 library available (`MbedTLS`). Required.")
endif ()

add_library(ah_x509 STATIC ${SOURCE_FILES})
target_include_directories(ah_x509
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_x509 PRIVATE ah_base ${LINKED_LIBRARIES})

set(
    TEST_FILES
    test/main.c
)

add_executable(ah_x509_tests ${TEST_FILES})
target_link_libraries(ah_x509_tests PRIVATE ah_base ah_x509 ah_unit)
