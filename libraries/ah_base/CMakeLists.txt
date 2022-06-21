cmake_minimum_required(VERSION 3.15)
project(ah_base C)
set(CMAKE_C_STANDARD 99)

set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(
    SOURCE_FILES
    include/ah/abort.h
    include/ah/alloc.h
    include/ah/assert.h
    include/ah/buf.h
    include/ah/conf.h
    include/ah/defs.h
    include/ah/err.h
    include/ah/internal/_loop.h
    include/ah/internal/_sock.h
    include/ah/internal/_task.h
    include/ah/internal/_tcp.h
    include/ah/internal/_time.h
    include/ah/internal/_udp.h
    include/ah/internal/collections/list.h
    include/ah/internal/collections/ring.h
    include/ah/internal/collections/slab.h
    include/ah/intrin.h
    include/ah/ip.h
    include/ah/lib.h
    include/ah/loop.h
    include/ah/math.h
    include/ah/rw.h
    include/ah/sock.h
    include/ah/task.h
    include/ah/tcp.h
    include/ah/time.h
    include/ah/udp.h
    src/abort.c
    src/buf.c
    src/collections/list.c
    src/collections/ring.c
    src/collections/slab.c
    src/err.c
    src/ip.c
    src/lib.c
    src/loop-evt.h
    src/loop.c
    src/math.c
    src/rw.c
    src/sock.c
    src/task.c
    src/tcp-in.c
    src/tcp-in.h
    src/tcp.c
    src/time.c
    src/udp-in.c
    src/udp-in.h
    src/udp.c
)

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    list(
        APPEND
        SOURCE_FILES
        include/ah/internal/_sock-bsd.h
        include/ah/internal/_time-darwin.h
        include/ah/internal/_loop-kqueue.h
        include/ah/internal/_task-kqueue.h
        include/ah/internal/_tcp-kqueue.h
        include/ah/internal/_udp-kqueue.h
        include/ah/internal/_buf-posix.h
        src/abort-posix.c
        src/buf-posix.c
        src/loop-kqueue.c
        src/sock-bsd.c
        src/task-kqueue.c
        src/tcp-bsd.c
        src/tcp-kqueue.c
        src/time-darwin.c
        src/udp-bsd.c
        src/udp-kqueue.c
    )
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    list(
        APPEND
        SOURCE_FILES
        include/ah/internal/_sock-bsd.h
        include/ah/internal/_buf-posix.h
        include/ah/internal/_loop-uring.h
        include/ah/internal/_task-uring.h
        include/ah/internal/_tcp-uring.h
        include/ah/internal/_time-uring.h
        include/ah/internal/_udp-uring.h
        src/abort-posix.c
        src/buf-posix.c
        src/loop-uring.c
        src/sock-bsd.c
        src/task-uring.c
        src/tcp-bsd.c
        src/tcp-uring.c
        src/time-uring.c
        src/udp-bsd.c
        src/udp-uring.c
    )
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    list(
        APPEND
        SOURCE_FILES
        include/ah/internal/_sock-bsd.h
        include/ah/internal/_loop-iocp.h
        include/ah/internal/_task-iocp.h
        include/ah/internal/_tcp-iocp.h
        include/ah/internal/_udp-iocp.h
        include/ah/internal/_buf-win32.h
        include/ah/internal/_time-win32.h
        src/abort-win32.c
        src/buf-win32.c
        src/loop-iocp.c
        src/sock-bsd.c
        src/task-iocp.c
        src/tcp-bsd.c
        src/tcp-iocp.c
        src/time-win32.c
        src/udp-bsd.c
        src/udp-iocp.c
        src/winapi.c
        src/winapi.h
    )
endif ()

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

set(
    TEST_FILES
    test/main.c
    test/test-buf.c
    test/test-err.c
    test/test-ip.c
    test/test-math.c
    test/test-sock.c
    test/test-task.c
    test/test-tcp.c
    test/test-time.c
    test/test-udp.c
)

add_executable(ah_base_tests ${TEST_FILES})
target_link_libraries(ah_base_tests PRIVATE ah_base ah_unit)
