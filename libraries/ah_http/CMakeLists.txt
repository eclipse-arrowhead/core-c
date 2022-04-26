cmake_minimum_required(VERSION 3.15)
project(ah_http C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/http.h
    include/ah/internal/http.h
    src/http-iheaders.c
    src/http-iheaders.h
    src/http-parser.c
)

add_library(ah_http STATIC ${SOURCE_FILES})
target_include_directories(ah_http
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_http PRIVATE ah_base)

set(
    TEST_FILES
    test/http-iheaders.c
    test/main.c
)

add_executable(ah_http_tests ${TEST_FILES})
target_link_libraries(ah_http_tests PRIVATE ah_base ah_http ah_unit)
