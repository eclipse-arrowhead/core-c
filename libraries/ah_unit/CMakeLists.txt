cmake_minimum_required(VERSION 3.15)
project(
    ah_unit
    LANGUAGES C
    VERSION 1.0.0
)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah/unit.h
    src/unit.c
)

add_library(ah_unit STATIC ${SOURCE_FILES})
target_include_directories(
    ah_unit
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)
target_link_libraries(ah_unit PRIVATE ah_base)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ah/internal/_unit.gen.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ah/internal/_unit.gen
    @ONLY
)
