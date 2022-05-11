cmake_minimum_required(VERSION 3.15)
project(ah_http C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/http.h
    include/ah/internal/_http.h
    src/http-body.c
    src/http-client.c
    src/http-parser.c
    src/http-parser.h
    src/http-server.c
)

add_library(ah_http STATIC ${SOURCE_FILES})
target_include_directories(ah_http
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_http PRIVATE ah_base)

set(
    TEST_FILES
    test/main.c
    test/test-http-client.c
    test/test-http-parser.c
    test/test-http-server.c
)

add_executable(ah_http_tests ${TEST_FILES})
target_link_libraries(ah_http_tests PRIVATE ah_base ah_http ah_unit)
