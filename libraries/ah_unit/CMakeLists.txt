cmake_minimum_required(VERSION 3.15)
project(ah_unit C)

set(CMAKE_C_STANDARD 99)
set(
    SOURCE_FILES
    include/ah/unit.h
    src/unit.c
)

add_library(ah_unit STATIC ${SOURCE_FILES})

target_include_directories(ah_unit
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)