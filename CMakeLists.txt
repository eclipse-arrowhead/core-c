cmake_minimum_required(VERSION 3.15)
project(arrowhead-core-c C)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

if (NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif ()

if (CMAKE_C_COMPILER_ID MATCHES "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    if (NOT CMAKE_BUILD_TYPE MATCHES "Debug")
        add_compile_options(-ffile-prefix-map=${PROJECT_SOURCE_DIR}/=)
    endif ()
elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    string(REGEX REPLACE "/W[0-9A-Za-z]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}") # Remove any existing warning flags.
    add_compile_options(/W4 /WX)
    add_compile_options(/DWINVER=0x0A00 /D_WIN32_WINNT=0x0A00) # Only support Windows 10 and up.
endif()

add_subdirectory(libraries)
add_subdirectory(tools)
