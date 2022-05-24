include(FindPackageHandleStandardArgs)

find_library(mbedcrypto_LIBRARY NAMES mbedcrypto)
find_path(mbedcrypto_INCLUDE_DIR NAMES mbedtls/platform.h)
find_package_handle_standard_args(mbedcrypto REQUIRED_VARS mbedcrypto_INCLUDE_DIR mbedcrypto_LIBRARY)

if (mbedcrypto_FOUND)
    mark_as_advanced(mbedcrypto_INCLUDE_DIR)
    mark_as_advanced(mbedcrypto_LIBRARY)

    if (NOT TARGET MbedTLS::mbedcrypto)
        add_library(MbedTLS::mbedcrypto IMPORTED STATIC)
        set_property(TARGET MbedTLS::mbedcrypto PROPERTY IMPORTED_LOCATION ${mbedcrypto_LIBRARY})
        target_include_directories(MbedTLS::mbedcrypto INTERFACE ${mbedcrypto_INCLUDE_DIR})
    endif()
endif()

find_library(mbedx509_LIBRARY NAMES mbedx509)
find_path(mbedx509_INCLUDE_DIR NAMES mbedtls/x509.h)
find_package_handle_standard_args(mbedx509 REQUIRED_VARS mbedx509_INCLUDE_DIR mbedx509_LIBRARY)

if (mbedx509_FOUND)
    mark_as_advanced(mbedx509_INCLUDE_DIR)
    mark_as_advanced(mbedx509_LIBRARY)

    if (NOT TARGET MbedTLS::mbedx509)
        add_library(MbedTLS::mbedx509 IMPORTED STATIC)
        set_property(TARGET MbedTLS::mbedx509 PROPERTY IMPORTED_LOCATION ${mbedx509_LIBRARY})
        set_target_properties(MbedTLS::mbedx509 PROPERTIES INTERFACE_LINK_LIBRARIES MbedTLS::mbedcrypto)
        target_include_directories(MbedTLS::mbedx509 INTERFACE ${mbedx509_INCLUDE_DIR})
    endif()
endif()

find_library(mbedtls_LIBRARY NAMES mbedtls)
find_path(mbedtls_INCLUDE_DIR NAMES mbedtls/ssl.h)
find_package_handle_standard_args(mbedtls REQUIRED_VARS mbedtls_INCLUDE_DIR mbedtls_LIBRARY)

if (mbedtls_FOUND)
    mark_as_advanced(mbedtls_INCLUDE_DIR)
    mark_as_advanced(mbedtls_LIBRARY)

    if (NOT TARGET MbedTLS::mbedtls)
        add_library(MbedTLS::mbedtls IMPORTED STATIC)
        set_property(TARGET MbedTLS::mbedtls PROPERTY IMPORTED_LOCATION ${mbedtls_LIBRARY})
        set_target_properties(MbedTLS::mbedtls PROPERTIES INTERFACE_LINK_LIBRARIES MbedTLS::mbedx509)
        target_include_directories(MbedTLS::mbedtls INTERFACE ${mbedtls_INCLUDE_DIR})
    endif()
endif()
