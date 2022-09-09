cmake_minimum_required(VERSION 3.15)

add_subdirectory(ah_base)
add_subdirectory(ah_consumer_service_discovery)
add_subdirectory(ah_http)
add_subdirectory(ah_json)
add_subdirectory(ah_mbedtls)
add_subdirectory(ah_unit)

find_package(Doxygen)

if (DOXYGEN_FOUND)
    add_custom_target(documentation ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM)
endif ()
