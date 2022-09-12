cmake_minimum_required(VERSION 3.15)
project(
    ah_http
    LANGUAGES C
    VERSION 1.0.0
)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/http.h
    include/ah/internal/_http.h
    src/http-client.c
    src/http-client.h
    src/http-parser.c
    src/http-parser.h
    src/http-server.c
    src/http-utils.h
    src/http-writer.c
    src/http-writer.h
)

add_library(ah_http STATIC ${SOURCE_FILES})
target_include_directories(
    ah_http
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)
target_link_libraries(ah_http PRIVATE ah_base)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ah/internal/_http.gen.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ah/internal/_http.gen
    @ONLY
)

set(
    TEST_FILES
    test/main.c
    test/test-http-parser.c
    test/test-http.c
)

add_executable(ah_http_tests ${TEST_FILES})
target_link_libraries(ah_http_tests PRIVATE ah_base ah_http ah_unit)
