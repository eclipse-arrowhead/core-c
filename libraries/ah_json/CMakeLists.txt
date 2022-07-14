cmake_minimum_required(VERSION 3.15)
project(ah_json C)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/json.h
    src/json.c
)

add_library(ah_json STATIC ${SOURCE_FILES})
target_include_directories(ah_json PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(ah_json PRIVATE ah_base)

set(
    TEST_FILES
    test/main.c
    test/test-json-parse.c
    test/test-json-str-compare.c
    test/test-json-str-unescape.c
)

add_executable(ah_json_tests ${TEST_FILES})
target_link_libraries(ah_json_tests PRIVATE ah_base ah_json ah_unit)
