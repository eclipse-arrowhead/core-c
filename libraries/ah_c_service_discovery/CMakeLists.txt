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
    src/service-discovery-lib-version.c
    src/service-discovery.c
)

add_library(ah_c_service_discovery STATIC ${SOURCE_FILES})
target_include_directories(
    ah_c_service_discovery
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)
target_link_libraries(ah_c_service_discovery PRIVATE ah_base ah_http ah_json)

file(
    GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/ah_i_c_service_discovery_lib_version.h
    CONTENT "\
#define AH_I_C_SERVICE_DISCOVERY_LIB_VERSION_STR \"${PROJECT_VERSION}\";\r\n\
#define AH_I_C_SERVICE_DISCOVERY_LIB_VERSION_MAJOR ${PROJECT_VERSION_MAJOR}u;\r\n\
#define AH_I_C_SERVICE_DISCOVERY_LIB_VERSION_MINOR ${PROJECT_VERSION_MINOR}u;\r\n\
#define AH_I_C_SERVICE_DISCOVERY_LIB_VERSION_PATCH ${PROJECT_VERSION_PATCH}u;\r\n"
    TARGET ah_c_service_discovery
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
