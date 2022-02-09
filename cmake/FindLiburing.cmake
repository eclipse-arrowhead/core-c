include(FindPackageHandleStandardArgs)

find_library(liburing_LIBRARY NAMES liburing uring)
find_path(liburing_INCLUDE_DIR NAMES liburing/io_uring.h)

find_package_handle_standard_args(liburing
    REQUIRED_VARS liburing_INCLUDE_DIR liburing_LIBRARY)

if (liburing_FOUND)
    mark_as_advanced(liburing_INCLUDE_DIR)
    mark_as_advanced(liburing_LIBRARY)
endif()

if (liburing_FOUND AND NOT TARGET liburing::liburing)
    add_library(liburing::liburing IMPORTED STATIC)
    set_property(TARGET liburing::liburing PROPERTY IMPORTED_LOCATION ${liburing_LIBRARY})
    target_include_directories(liburing::liburing INTERFACE ${liburing_INCLUDE_DIR})
endif()
