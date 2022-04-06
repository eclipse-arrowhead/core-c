cmake_minimum_required(VERSION 3.12)
project(ah_base C)

set(CMAKE_C_STANDARD 99)
set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(
    SOURCE_FILES
    include/ah/abort.h
    include/ah/alloc.h
    include/ah/assert.h
    include/ah/buf.h
    include/ah/defs.h
    include/ah/err.h
    include/ah/ip.h
    include/ah/lib.h
    include/ah/loop-internal.h
    include/ah/loop.h
    include/ah/math.h
    include/ah/sock.h
    include/ah/task.h
    include/ah/tcp.h
    include/ah/time.h
    include/ah/udp.h
    src/abort.c
    src/alloc.c
    src/err.c
    src/lib.c
    src/loop.c
    src/math.c
    src/sock-internal.h
    src/sock.c
    src/task.c
    src/tcp.c
    src/time.c
    src/udp.c
)
set(
    TEST_FILES
    test/err.c
    test/main.c
    test/math.c
    test/sock.c
    test/task.c
    test/time.c
    test/udp.c
)

add_library(ah_base STATIC ${SOURCE_FILES})

target_include_directories(
    ah_base
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${GENERATED_DIR}>
)

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    include(FindLiburing)
    target_link_libraries(ah_base liburing::liburing)
endif ()

add_executable(ah_base_tests ${TEST_FILES})

target_link_libraries(ah_base_tests PRIVATE ah_base ah_unit)

add_custom_target(mkdir_generated
    COMMAND ${CMAKE_COMMAND} -E make_directory "${GENERATED_DIR}"
    BYPRODUCTS "${GENERATED_DIR}"
    VERBATIM)

add_dependencies(ah_base mkdir_generated)

include(FindGit)

if (GIT_FOUND)
    set(GIT_METADATA_HEADER "${GENERATED_DIR}/ah_i_git_metadata.h")
    add_custom_target(
        generate_git_metadata_header
        COMMAND git_metadata_to_header "${GIT_METADATA_HEADER}" AH_I_
        BYPRODUCTS "${GIT_METADATA_HEADER}"
        DEPENDS "${CMAKE_SOURCE_DIR}/.git/refs/heads/master"
        COMMENT "Generating ${GIT_METADATA_HEADER}"
        VERBATIM)
    add_dependencies(ah_base generate_git_metadata_header)
else ()
    message(FATAL_ERROR "`git` not found. Required.")
endif ()
