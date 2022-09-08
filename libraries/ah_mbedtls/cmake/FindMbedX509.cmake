include(FindPackageHandleStandardArgs)

find_library(MbedX509_LIBRARY NAMES mbedx509)
find_path(MbedX509_INCLUDE_DIR NAMES mbedtls/x509.h)
find_package_handle_standard_args(MbedX509 REQUIRED_VARS MbedX509_INCLUDE_DIR MbedX509_LIBRARY)

if (MbedX509_FOUND)
    mark_as_advanced(MbedX509_INCLUDE_DIR)
    mark_as_advanced(MbedX509_LIBRARY)

    find_package(MbedCrypto)

    if (NOT TARGET MbedTLS::mbedx509)
        add_library(MbedTLS::mbedx509 IMPORTED STATIC)
        set_property(TARGET MbedTLS::mbedx509 PROPERTY IMPORTED_LOCATION ${MbedX509_LIBRARY})
        set_target_properties(MbedTLS::mbedx509 PROPERTIES INTERFACE_LINK_LIBRARIES MbedTLS::mbedcrypto)
        target_include_directories(MbedTLS::mbedx509 INTERFACE ${MbedX509_INCLUDE_DIR})
    endif ()
endif ()
