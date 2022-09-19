// SPDX-License-Identifier: EPL-2.0

#ifndef AH_DEFS_H_
#define AH_DEFS_H_

/**
 * @file
 * Platform, compiler, attribute and type definitions.
 *
 * This file is meant to be included from virtually every header file of the
 * base library. It contains macros for checking what the targeted platform is,
 * what compiler is being used, what relevant platform and compiler features
 * are available, and so on. Finally, it performs some tests to ensure that the
 * targeted platform and compiler are supported by the library.
 */

#if defined(AH_DOXYGEN)
// Do nothing.
#elif defined(__APPLE__)
# define AH_IS_DARWIN 1
#elif defined(__linux__)
# define AH_IS_LINUX 1
#elif defined(_WIN32)
# define AH_IS_WIN32 1
#endif

#ifndef AH_IS_DARWIN
/**
 * Indicates whether the targeted platform is Darwin.
 */
# define AH_IS_DARWIN 0
#endif
#ifndef AH_IS_LINUX
/**
 * Indicates whether the targeted platform is Linux.
 */
# define AH_IS_LINUX 0
#endif
#ifndef AH_IS_WIN32
/**
 * Indicates whether the targeted platform is WIN32.
 */
# define AH_IS_WIN32 0
#endif

#ifndef AH_USE_IOCP
/**
 * Indicates whether the Windows I/O Completion Ports API is used internally to
 * manage asynchronous events.
 */
# define AH_USE_IOCP AH_IS_WIN32
#endif
#ifndef AH_USE_KQUEUE
/**
 * Indicates whether the BSD Kernel Queue API is used internally to manage
 * asynchronous events.
 */
# define AH_USE_KQUEUE AH_IS_DARWIN
#endif
#ifndef AH_USE_URING
/**
 * Indicates whether the Linux io_uring API is used internally to manage
 * asynchronous events.
 */
# define AH_USE_URING AH_IS_LINUX
#endif

/**
 * Indicates whether or not a BSD sockets implementation is available on the
 * targeted platform.
 */
#define AH_HAS_BSD_SOCKETS (AH_IS_DARWIN || AH_IS_LINUX || AH_IS_WIN32)

/**
 * Indicates whether the targeted platform is at least loosely POSIX-compliant.
 */
#define AH_HAS_POSIX (AH_IS_DARWIN || AH_IS_LINUX)

#if defined(AH_DOXYGEN)
// Do nothing.
#elif defined(__clang__)
# if __clang_major__ < 13
#  error "Only clang versions 13 and above are supported for this library."
# endif
# define AH_VIA_CLANG 1
#elif defined(__GNUC__)
# if __GNUC__ < 9
#  error "Only GCC versions 9 and above are supported for this library."
# endif
# define AH_VIA_GCC 1
#elif defined(_MSC_VER)
# if _MSC_VER < 1930
#  error "Only Visual Studio 2022 (17.0) and above are supported for this library."
# endif
# define AH_VIA_MSVC 1
#else
# warning "The library seems to be compiled with an unsupported compiler."
#endif

#ifndef AH_VIA_CLANG
/**
 * Indicates whether or not the Clang compiler is being used.
 */
# define AH_VIA_CLANG 0
#endif
#ifndef AH_VIA_GCC
/**
 * Indicates whether or not the GCC compiler is being used.
 */
# define AH_VIA_GCC 0
#endif
#ifndef AH_VIA_MSVC
/**
 * Indicates whether or not the Microsoft Visual Studio compiler (MSVC++) is being used.
 */
# define AH_VIA_MSVC 0
#endif

#if (-1 & 3) != 3
# error "Only computer architectures with two's complement signed integers are supported for this library."
#endif

#if AH_VIA_CLANG || AH_VIA_GCC
# define ah_extern   __attribute__((visibility("default"), unused))
# define ah_noreturn __attribute__((noreturn))
#elif AH_VIA_MSVC
# define ah_extern   __declspec(dllexport)
# define ah_noreturn __declspec(noreturn)
#else
/**
 * Specified before a function declaration or definition to make it available
 * when linking.
 */
# define ah_extern

/**
 * Specified before a function declaration or definition to indicate that the
 * function in question never returns.
 */
# define ah_noreturn
#endif

/**
 * @name Error Type
 *
 * This type is used to indicate that an error code is being returned or
 * provided.
 *
 * @see err.h
 *
 * @{
 */

/**
 * Signed integer type used to hold an error code.
 */
typedef int ah_err_t;

/** @} */

/**
 * @name Forward Declarations
 *
 * The following are the typedefs for all structures and unions specified in
 * this library. Maintaining this list here means that it is enough to include
 * this header if wanting to point to any type specified in this library, rather
 * than having to incur the compile-time cost of including the header file where
 * it is specified in full.
 *
 * @{
 */

typedef struct ah_buf ah_buf_t;
typedef struct ah_ipaddr_v4 ah_ipaddr_v4_t;
typedef struct ah_ipaddr_v6 ah_ipaddr_v6_t;
typedef struct ah_loop ah_loop_t;
typedef struct ah_rw ah_rw_t;
typedef struct ah_sockaddr_any ah_sockaddr_any_t;
typedef struct ah_sockaddr_ip ah_sockaddr_ip_t;
typedef struct ah_sockaddr_ipv4 ah_sockaddr_ipv4_t;
typedef struct ah_sockaddr_ipv6 ah_sockaddr_ipv6_t;
typedef struct ah_task ah_task_t;
typedef struct ah_tcp_accept ah_tcp_accept_t;
typedef struct ah_tcp_conn ah_tcp_conn_t;
typedef struct ah_tcp_conn_cbs ah_tcp_conn_cbs_t;
typedef struct ah_tcp_conn_obs ah_tcp_conn_obs_t;
typedef struct ah_tcp_in ah_tcp_in_t;
typedef struct ah_tcp_listener ah_tcp_listener_t;
typedef struct ah_tcp_listener_cbs ah_tcp_listener_cbs_t;
typedef struct ah_tcp_listener_obs ah_tcp_listener_obs_t;
typedef struct ah_tcp_out ah_tcp_out_t;
typedef struct ah_tcp_trans ah_tcp_trans_t;
typedef struct ah_tcp_trans_vtab ah_tcp_trans_vtab_t;
typedef struct ah_time ah_time_t;
typedef struct ah_udp_group_ipv4 ah_udp_group_ipv4_t;
typedef struct ah_udp_group_ipv6 ah_udp_group_ipv6_t;
typedef struct ah_udp_in ah_udp_in_t;
typedef struct ah_udp_out ah_udp_out_t;
typedef struct ah_udp_sock ah_udp_sock_t;
typedef struct ah_udp_sock_cbs ah_udp_sock_cbs_t;
typedef struct ah_udp_sock_obs ah_udp_sock_obs_t;
typedef struct ah_udp_trans ah_udp_trans_t;
typedef struct ah_udp_trans_vtab ah_udp_trans_vtab_t;

typedef union ah_sockaddr ah_sockaddr_t;
typedef union ah_udp_group ah_udp_group_t;

/** @} */

#endif
