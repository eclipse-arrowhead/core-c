    @dir ah_base @brief Base library.

This library provides the foundation upon which most other Core C libraries
depend. It most significantly exposes a cross-platform API over some I/O
utilities provided by the targeted platforms, such as TCP/IP networking. Most of
the I/O operations exposed by this library are provided as asynchronous
functions, which is to say that their results are provided after they return by
invoking given callback functions. All asynchronous functionality of the library
is managed via so-called event loops (see include/ah/loop.h), which can be seen
as single-threaded event queues managed by this library.

As managing events require several kinds of peripheral functionality, some of
that is also exposed, or made configurable (see include/ah/conf.h), by this
library. Buffers, error codes, safe math functions and time querying are some
notable examples.

Another primary purpose of this library is to gather together key functionality
that must be ported in order for this and most other official Arrowhead Core C
libraries to support another platform. While there may be some exceptions, this
library being ported to a certain platform should mean that most officials
libraries can run on that platform.

Asynchronous I/O was popularized primarily via libuv, which is the C library on
top of which the now ubiquitous Node.js JavaScript runtime is built. That
library, as well as the alternatives we know of, such as libevent and libev,
were designed primarily to support creating server applications for the World
Wide Web. As such, they make rather strong assumptions about the facilities of
the operating systems required to run them (such as the availability of
filesystems and inter-process signaling), as well as the hardware capabilities
of those servers. In contrast, this base library, and most of its official
companion libraries, are designed primarily to support creating machine-centric
applications, or system-of-systems. Many of those machines may have limited
software and hardware capabilities, such as not being able to run full operating
systems or not having access to significant compute or memory facilities. While
a WWW server will typically have at least hundreds of megabytes of RAM and disk
storage, an Arrowhead system running this library may have hundreds of kilobytes
of RAM and ROM.

### Dependencies

Every supported platform may depend on particular libraries distributed by the
creator of the platform. However, as these libraries tend to be distributed with
the compiler for the platform, you will typically not need to do anything beyond
making sure the compiler and/or appropriate SDKs to be installed and available.

An exception to this is, however, the use of [io_uring][uring] on the Linux
platform, which requires the `liburing` library. If you want to compile this
library for Linux, `liburing-2.2` or later is required. If you have a working
Internet connection, CMake will attempt to download and compile the library
automatically. If, however, any version of `liburing` is already installed and
available on your system, that version will be used without any download being
initiated.

[uring]: https://unixism.net/loti/what_is_io_uring.html

### Porting

If the current set of platforms supported by this library is insufficient, you
may want to extend that set by porting it to another one. To do so, you will
need to do the following:

1. __Update the `CMakeLists.txt` file in the root folder of this library.__ In
   particular, you must make sure that any source files and platform libraries
   your port depends on are included when it is built. As the
   [`CMAKE_SYSTEM_NAME`][cmsn] is used to determine what platform is being
   targeted, you should conditionally add whatever files and libraries are
   needed when it has a suitable value. If your port further depends on certain
   hardware platforms being targeted, a certain compiler being available, etc.
   them you may have to use [other variables provide by CMake][cmov].
2. __Determine what source files you need to write and create them.__ There are
   platform-specific source files in two locations: (A) in the
   `/libraries/ah_base/include/ah/internal/` folder and (B) the
   `/libraries/ab_base/src/` folder. The former folder contains header files
   that include and/or define whatever is needed for the various structures of
   this library to contain the correct fields and have sizes known at
   compile-time. The second folder contains the source files implementing the
   functions of this library. Every platform-specific source file has a name
   ending with a dash and a special name that identifies the platform it
   targets or a special library available on multiple platforms. You can, for
   example, find files ending with `-win32.h`, `-posix.h`, `-kqueue.h`,
   `-uring.c` and `-darwin.c`. Decide what file ending or endings are most
   appropriate for the platform you target, and make sure that all files exist
   you will need write. If your platform supports a library or standard already
   supported by another platform, such as KQueue or POSIX, you may want to use
   those files rather than write new ones.
3. __Add all source files you created, and existing platform-specific ones__
   __you wish to use, to your platform's source file list in the CMake__
   __project file__. That source list, which must include both header files and
   source files, must be appended to the `SOURCE_FILES` variable of the
   `/libraries/ah_base/CMakeLists.txt` file.
4. __Make the library compile for your platform.__ When you first try to
   compile for your platform, the compiler is likely going to fail because your
   source files are not containing any compilation units. If you are using
   either of the Clang or GCC compilers, you can suppress this by removing the
   `-Werror` flag from the `add_compile_options()` command in the
   `/CMakeLists.txt` file at the root of the Core C repository. Now, you must
   add every function the compiler or linker is missing in order to complete
   the build. Those functions will generally have names starting with `ah_`. If
   you need help regarding what files to place the functions in, refer to the
   source files of the already supported platforms. You may leave the function
   bodies empty, for the time being. When compiling and linking finishes
   without errors, try to compile and run the `ah_base_tests` project. It
   should run, but notify you about various assertions that are failing.
5. __Add a suitable platform macro to `/libraries/ah_base/include/ah/defs.h`.__
   You are likely going to need a macro named `AH_IS_<YOUR-PLATFORMS-NAME>`
   when you later make sure your platform-specific header files are included
   properly. Add the macro and make sure it is set to `1` or `0` depending on
   if your platform is being targeted. If your target is POSIX-compliant, uses
   a library already used by some other platform, and so on, you may also wish
   to modify other macros to reflect these facts.
6. __Make sure your platform-specific internal header files are included only__
   __when compiling for your platform.__ If you, for example, have created a
   header file named `/libraries/ah_base/include/ah/internal/_time-android.h`,
   you must modify `/libraries/ah_base/include/ah/internal_time.h` such that it
   includes the created file when the targeted platform is `Android`. The same
   kind of treatment must be given to every relevant internal header file.
7. __Add correctly named include guards to your internal header files.__ The
   name of each include guard is derived from the path of the file relative to
   the `/libraries/ah_base/include/` directory. That relative path has every
   path separator, dash and dot replaced by an underscore. A trailing
   underscore is also added. Any double underscores are replaced by a single
   underscore. If, for example, the header file in question is the same
   `_time-android.h` file we mentioned in the last step, the include guard must
   be named `AH_INTERNAL_TIME_ANDROID_H_`.
8. __Implement all platform-specific functions and make CMake download and/or__
   __find any required libraries.__ A strong indicator that you are approaching
   the completion of this step is that you can execute `ah_base_tests` without
   any failed assertions. You may want to add more tests to this application to
   cover potential issues it currently cannot identify. Please refer to the
   existing implementations for guidance regarding how to validate function
   arguments, internal state, and so on.
9. __Update the documentation.__ Now that another platform is supported, the
   documentation must be updated to reflect this support. In particular, the
   following files must be updated:
    - `/libraries/README.md` The section on supported platforms and compilers
      must include the new platform.
    - `/libraries/ah_base/README.md` If your platform requires certain libraries
      or build tools, it must be documented in this file.
    - `/libraries/ah_base/include/ah/defs.h` Any macros you added or updated
      may need to be documented.
    - _Every function or callback that may return or provide an error code from_
      _your platform implementation._ For example, ah_task_schedule_at() and
      ah_tcp_conn_cbs::on_open both rely on platform-specific implementations
      that could produce error codes unique to each respective platform. Every
      place where error codes specific to your platform could be presented must
      be updated.
10. __If relevant, present your port to the Eclipse Arrowhead leads and__
    __committers.__ If your port becomes an official part of the Eclipse
    Arrowhead project, you may get help in maintaining your port over time.
    More information about contributing to Eclipse Arrowhead can be read on the
    Overview page if you are reading the Doxygen documentation. If you are
    reading on GitHub or directly in the source code, that information is
    available in `/libraries/README.md`.

[cmsn]: https://cmake.org/cmake/help/latest/variable/CMAKE_SYSTEM_NAME.html

[cmov]: https://cmake.org/cmake/help/latest/manual/cmake-variables.7.html
