// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_DEFS_H_
#define AH_DEFS_H_

#if defined(__APPLE__)
#    define AH_IS_DARWIN 1
#elif defined(__linux__)
#    define AH_IS_LINUX 1
#elif defined(_WIN32)
#    define AH_IS_WIN32 1
#endif

#ifndef AH_IS_DARWIN
#    define AH_IS_DARWIN 0
#endif
#ifndef AH_IS_LINUX
#    define AH_IS_LINUX 0
#endif
#ifndef AH_IS_WIN32
#    define AH_IS_WIN32 0
#endif

#ifndef AH_USE_IOCP
#    define AH_USE_IOCP AH_IS_WIN32
#endif
#ifndef AH_USE_KQUEUE
#    define AH_USE_KQUEUE AH_IS_DARWIN
#endif
#ifndef AH_USE_URING
#    define AH_USE_URING AH_IS_LINUX
#endif

#define AH_HAS_BSD_SOCKETS (AH_USE_IOCP || AH_USE_KQUEUE || AH_USE_URING)
#define AH_HAS_POSIX       (AH_USE_KQUEUE || AH_USE_URING)

#if defined(__clang__)
#    if __clang_major__ < 13
#        error "Only clang versions 13 and above are supported for this library."
#    endif
#    define AH_VIA_CLANG 1
#elif defined(__GNUC__)
#    if __GNUC__ < 9
#        error "Only GCC versions 9 and above are supported for this library."
#    endif
#    define AH_VIA_GCC 1
#elif defined(_MSC_VER)
#    if _MSC_VER < 1930
#        error "Only Visual Studio 2022 (17.0) and above are supported for this library."
#    endif
#    define AH_VIA_MSVC 1
#else
#    warning "The library seems to be compiled with an unsupported compiler."
#endif

#ifndef AH_VIA_CLANG
#    define AH_VIA_CLANG 0
#endif
#ifndef AH_VIA_GCC
#    define AH_VIA_GCC 0
#endif
#ifndef AH_VIA_MSVC
#    define AH_VIA_MSVC 0
#endif

#if AH_VIA_MSVC && !AH_IS_WIN32
#    error "MSVC must only be used to compile for the Windows platform."
#endif

#if (-1 & 3) != 3
#    error "Only computer architectures with two's complement signed integers are supported for this library."
#endif

#if AH_VIA_CLANG || AH_VIA_GCC
#    define ah_extern        __attribute__((visibility("default"), unused))
#    define ah_extern_inline static inline __attribute__((unused))
#    define ah_noreturn      __attribute__((noreturn))
#    define ah_unused        __attribute__((unused))

#    define ah_likely(expr)   __builtin_expect(!!(expr), 1)
#    define ah_trap()         __builtin_trap()
#    define ah_unlikely(expr) __builtin_expect(!!(expr), 0)
#    define ah_unreachable()  __builtin_unreachable()

#    define ah_p_add_overflow(a, b, result) __builtin_add_overflow((a), (b), (result))
#    define ah_p_mul_overflow(a, b, result) __builtin_mul_overflow((a), (b), (result))
#    define ah_p_sub_overflow(a, b, result) __builtin_sub_overflow((a), (b), (result))
#elif AH_VIA_MSVC
#    pragma intrinsic(__debugbreak)

#    define ah_extern        __declspec(dllexport)
#    define ah_extern_inline static inline
#    define ah_noreturn      __declspec(noreturn)
#    define ah_unused

#    define ah_likely(expr)   expr
#    define ah_trap()         __debugbreak()
#    define ah_unlikely(expr) expr
#    define ah_unreachable()  __assume(0)
#endif

typedef int ah_err_t;

typedef struct ah_buf ah_buf_t;
typedef struct ah_bufvec ah_bufvec_t;
typedef struct ah_ipaddr_v4 ah_ipaddr_v4_t;
typedef struct ah_ipaddr_v6 ah_ipaddr_v6_t;
typedef struct ah_loop ah_loop_t;
typedef struct ah_loop_opts ah_loop_opts_t;
typedef struct ah_sockaddr_any ah_sockaddr_any_t;
typedef struct ah_sockaddr_ip ah_sockaddr_ip_t;
typedef struct ah_sockaddr_ipv4 ah_sockaddr_ipv4_t;
typedef struct ah_sockaddr_ipv6 ah_sockaddr_ipv6_t;
typedef struct ah_task ah_task_t;
typedef struct ah_task_opts ah_task_opts_t;
typedef struct ah_tcp_listen_ctx ah_tcp_listen_ctx_t;
typedef struct ah_tcp_read_ctx ah_tcp_read_ctx_t;
typedef struct ah_tcp_sock ah_tcp_sock_t;
typedef struct ah_tcp_write_ctx ah_tcp_write_ctx_t;
typedef struct ah_time ah_time_t;
typedef struct ah_udp_group_ipv4 ah_udp_group_ipv4_t;
typedef struct ah_udp_group_ipv6 ah_udp_group_ipv6_t;
typedef struct ah_udp_recv_ctx ah_udp_recv_ctx_t;
typedef struct ah_udp_send_ctx ah_udp_send_ctx_t;
typedef struct ah_udp_sock ah_udp_sock_t;

typedef union ah_sockaddr ah_sockaddr_t;
typedef union ah_udp_group ah_udp_group_t;

typedef struct ah_i_loop_evt ah_i_loop_evt_t;
typedef struct ah_i_loop_evt_page ah_i_loop_evt_page_t;

#endif
