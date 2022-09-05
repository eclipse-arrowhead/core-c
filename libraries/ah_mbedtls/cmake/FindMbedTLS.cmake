include(FindPackageHandleStandardArgs)

find_library(MbedTLS_LIBRARY NAMES mbedtls)
find_path(MbedTLS_INCLUDE_DIR NAMES mbedtls/ssl.h)
find_package_handle_standard_args(MbedTLS REQUIRED_VARS MbedTLS_INCLUDE_DIR MbedTLS_LIBRARY)

if (MbedTLS_FOUND)
    mark_as_advanced(MbedTLS_INCLUDE_DIR)
    mark_as_advanced(MbedTLS_LIBRARY)

    find_package(MbedX509)

    if (NOT TARGET MbedTLS::mbedtls)
        add_library(MbedTLS::mbedtls IMPORTED STATIC)
        set_property(TARGET MbedTLS::mbedtls PROPERTY IMPORTED_LOCATION ${MbedTLS_LIBRARY})
        set_target_properties(MbedTLS::mbedtls PROPERTIES INTERFACE_LINK_LIBRARIES MbedTLS::mbedx509)
        target_include_directories(MbedTLS::mbedtls INTERFACE ${MbedTLS_INCLUDE_DIR})
    endif ()
endif ()
