include(FindPackageHandleStandardArgs)

find_library(MbedCrypto_LIBRARY NAMES mbedcrypto)
find_path(MbedCrypto_INCLUDE_DIR NAMES mbedtls/platform.h)
find_package_handle_standard_args(MbedCrypto REQUIRED_VARS MbedCrypto_INCLUDE_DIR MbedCrypto_LIBRARY)

if (MbedCrypto_FOUND)
    mark_as_advanced(MbedCrypto_INCLUDE_DIR)
    mark_as_advanced(MbedCrypto_LIBRARY)

    if (NOT TARGET MbedTLS::mbedcrypto)
        add_library(MbedTLS::mbedcrypto IMPORTED STATIC)
        set_property(TARGET MbedTLS::mbedcrypto PROPERTY IMPORTED_LOCATION ${MbedCrypto_LIBRARY})
        target_include_directories(MbedTLS::mbedcrypto INTERFACE ${MbedCrypto_INCLUDE_DIR})
    endif ()
endif ()
