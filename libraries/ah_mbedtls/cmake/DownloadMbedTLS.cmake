cmake_minimum_required(VERSION 3.15)

# Download, install and find MBedTLS.

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/DownloadMbedTLS.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-download/CMakeLists.txt")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-download"
)
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-download"
)
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_BINARY_DIR}/mbedtls-install")

find_package(MbedTLS)
