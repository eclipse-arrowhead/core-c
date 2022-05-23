include(FindPackageHandleStandardArgs)

find_library(wolfssl_LIBRARY NAMES wolfssl uring)
find_path(wolfssl_INCLUDE_DIR NAMES wolfssl/ssl.h)

find_package_handle_standard_args(wolfssl
    REQUIRED_VARS wolfssl_INCLUDE_DIR wolfssl_LIBRARY)

if (wolfssl_FOUND)
    mark_as_advanced(wolfssl_INCLUDE_DIR)
    mark_as_advanced(wolfssl_LIBRARY)
endif()

if (wolfssl_FOUND AND NOT TARGET wolfssl::wolfssl)
    add_library(wolfssl::wolfssl IMPORTED STATIC)
    set_property(TARGET wolfssl::wolfssl PROPERTY IMPORTED_LOCATION ${wolfssl_LIBRARY})
    target_include_directories(wolfssl::wolfssl INTERFACE ${wolfssl_INCLUDE_DIR})
endif()
