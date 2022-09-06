cmake_minimum_required(VERSION 3.15)

# Download, install and find liburing.

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/DownloadLiburing.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/liburing-download/CMakeLists.txt")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/liburing-download"
)
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/liburing-download"
)
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_BINARY_DIR}/liburing-src/src")

find_package(Liburing)
