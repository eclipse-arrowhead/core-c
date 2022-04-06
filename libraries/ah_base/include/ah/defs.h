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

#define AH_USE_BSD_SOCKETS (AH_USE_IOCP || AH_USE_KQUEUE || AH_USE_URING)
#define AH_USE_POSIX (AH_USE_KQUEUE || AH_USE_URING)

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
#    define ah_extern __attribute__((visibility("default"), unused))
#else
#    define ah_extern
#endif

#if AH_VIA_GCC || AH_VIA_CLANG
#    define ah_likely(expr)   __builtin_expect(!!(expr), 1)
#    define ah_unlikely(expr) __builtin_expect(!!(expr), 0)
#else
#    define ah_likely(expr)
#    define ah_unlikely(expr)
#endif

#if AH_VIA_GCC || AH_VIA_CLANG
#    define ah_noreturn __attribute__((noreturn))
#elif AH_VIA_MSVC
#    define ah_noreturn __declspec__((noreturn))
#else
#    define ah_noreturn
#endif

#if AH_VIA_GCC || AH_VIA_CLANG
#    define ah_unused __attribute__((unused))
#else
#    define ah_unused
#endif

struct ah_buf;
struct ah_bufvec;
struct ah_ipaddr_v4;
struct ah_ipaddr_v6;
struct ah_loop;
struct ah_loop_opts;
struct ah_sockaddr_any;
struct ah_sockaddr_ip;
struct ah_sockaddr_ipv4;
struct ah_sockaddr_ipv6;
struct ah_task;
struct ah_tcp_read_ctx;
struct ah_tcp_sock;
struct ah_tcp_write_ctx;
struct ah_time;
struct ah_udp_group_ipv4;
struct ah_udp_group_ipv6;
struct ah_udp_recv_ctx;
struct ah_udp_send_ctx;
struct ah_udp_sock;

union ah_sockaddr;
union ah_udp_group;

#endif
