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

file(
    GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/ah_i_unit_lib_version.h
    CONTENT "\
#define AH_I_UNIT_LIB_VERSION_STR \"${PROJECT_VERSION}\";\r\n\
#define AH_I_UNIT_LIB_VERSION_MAJOR ${PROJECT_VERSION_MAJOR}u;\r\n\
#define AH_I_UNIT_LIB_VERSION_MINOR ${PROJECT_VERSION_MINOR}u;\r\n\
#define AH_I_UNIT_LIB_VERSION_PATCH ${PROJECT_VERSION_PATCH}u;\r\n"
    TARGET ah_unit
)
