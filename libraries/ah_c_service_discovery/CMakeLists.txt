cmake_minimum_required(VERSION 3.15)
project(
    ah_c_service_discovery
    LANGUAGES C
    VERSION 0.0.0
)
set(CMAKE_C_STANDARD 99)

set(
    SOURCE_FILES
    include/ah-c/service-discovery.h
    include/ah-c/internal/_service-discovery.h
    src/service-discovery.c
)

add_library(ah_c_service_discovery STATIC ${SOURCE_FILES})
target_include_directories(
    ah_c_service_discovery
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)
target_link_libraries(ah_c_service_discovery PRIVATE ah_base ah_http ah_json)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ah-c/internal/_service-discovery.gen.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ah-c/internal/_service-discovery.gen
    @ONLY
)

set(
    TEST_FILES
    test/main.c
)

add_executable(ah_c_service_discovery_tests ${TEST_FILES})
target_link_libraries(
    ah_c_service_discovery_tests
    PRIVATE ah_base
            ah_c_service_discovery
            ah_unit
)
