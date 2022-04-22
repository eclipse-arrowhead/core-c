cmake_minimum_required(VERSION 3.15)
project(ah_protocol_http C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/http.h
    src/http.c
)

add_library(ah_protocol_http STATIC ${SOURCE_FILES})
target_include_directories(ah_protocol_http
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_protocol_http PRIVATE ah_base)

set(
    TEST_FILES
    test/main.c
)

add_executable(ah_protocol_http_tests ${TEST_FILES})
target_link_libraries(ah_protocol_http_tests PRIVATE ah_base ah_protocol_http ah_unit)