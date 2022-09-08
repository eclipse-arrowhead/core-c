include(FindPackageHandleStandardArgs)

find_library(Liburing_LIBRARY NAMES liburing uring)
find_path(Liburing_INCLUDE_DIR NAMES liburing.h liburing/io_uring.h)

find_package_handle_standard_args(Liburing REQUIRED_VARS Liburing_INCLUDE_DIR Liburing_LIBRARY)

if (Liburing_FOUND)
    mark_as_advanced(Liburing_INCLUDE_DIR)
    mark_as_advanced(Liburing_LIBRARY)

    if (NOT TARGET Liburing::liburing)
        add_library(Liburing::liburing IMPORTED STATIC)
        set_property(TARGET Liburing::liburing PROPERTY IMPORTED_LOCATION ${Liburing_LIBRARY})
        target_include_directories(Liburing::liburing INTERFACE ${Liburing_INCLUDE_DIR})
    endif()
endif()
