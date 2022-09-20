// SPDX-License-Identifier: EPL-2.0

#ifndef AH_CONF_H_
#define AH_CONF_H_

/**
 * @file
 * Library configuration.
 *
 * This file contains various macro definitions that are used to affect the
 * internal behaviour of the base library in various ways. You may chose to
 * update this file directly, define the @c AH_CONF_INCLUDE macro as a string
 * referring to a custom header file, or, if your compiler supports the
 * @c __has_include macro, add a custom file called @c ah-base-conf-custom.h at
 * a filesystem location part of your compiler's include path. Whatever method
 * you chose to use, define the macros you wish to modify to override their
 * default values.
 */

#if !defined(AH_CONF_INCLUDE) && defined(__has_include) && __has_include("ah-base-conf-custom.h")
# define AH_CONF_INCLUDE "ah-base-conf-custom.h"
#endif

#ifdef AH_CONF_INCLUDE
# include AH_CONF_INCLUDE
#endif

#ifndef AH_CONF_IS_CONSTRAINED
# if defined(__arm__) && !defined(__aarch64__) && !defined(AH_DOXYGEN)
#  define AH_CONF_IS_CONSTRAINED 1
# endif
#endif
#ifndef AH_CONF_IS_CONSTRAINED
/**
 * Indicates whether or not the targeted platform qualifies as being
 * @e "constrained".
 *
 * If set to @c 1, internal buffers and other resources may be configured to
 * require less memory.
 */
# define AH_CONF_IS_CONSTRAINED 0
#endif

#ifndef AH_CONF_CALLOC
/**
 * Used C99 @c calloc() implementation.
 *
 * Allocates zeroed memory for arrays.
 */
# define AH_CONF_CALLOC calloc
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_FREE
/**
 * Used C99 @c free() implementation.
 *
 * Releases memory allocated via the functions specified by @c AH_CONF_CALLOC
 * and @c AH_CONF_MALLOC.
 */
# define AH_CONF_FREE free
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_IOCP_COMPLETION_ENTRY_BUFFER_SIZE
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_IOCP_COMPLETION_ENTRY_BUFFER_SIZE 4u
# else
/**
 * [IOCP] The number I/O Completion Port @c OVERLAPPED_ENTRY instances to be
 * part of the buffer used when polling for completed events.
 *
 * A higher value @e may lead to higher event loop throughput.
 */
#  define AH_CONF_IOCP_COMPLETION_ENTRY_BUFFER_SIZE 128u
# endif
#endif

#ifndef AH_CONF_IOCP_DEFAULT_CAPACITY
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_IOCP_DEFAULT_CAPACITY 32u
# else
/**
 * [IOCP] Default ah_loop @c capacity for platforms relying on Windows I/O
 * Completion Ports.
 *
 * A higher value @e may lead to higher event loop throughput.
 */
#  define AH_CONF_IOCP_DEFAULT_CAPACITY 256u
# endif
#endif

#ifndef AH_CONF_KQUEUE_DEFAULT_CAPACITY
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_KQUEUE_DEFAULT_CAPACITY 32u
# else
/**
 * [KQueue] Default ah_loop @c capacity for platforms relying on BSD Kernel
 * Queue API.
 *
 * A higher value @e may lead to higher event loop throughput.
 */
#  define AH_CONF_KQUEUE_DEFAULT_CAPACITY 1024u
# endif
#endif

#ifndef AH_CONF_MALLOC
/**
 * Used C99 @c malloc() implementation.
 *
 * Allocates uninitialized chunks of memory.
 */
# define AH_CONF_MALLOC malloc
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_PALLOC
# if !defined(NDEBUG) && !defined(AH_DOXYGEN)
#  define AH_CONF_PALLOC() AH_CONF_CALLOC(1u, AH_CONF_PSIZE)
# else
/**
 * Function used to allocate pages, as described in alloc.h.
 *
 * Allocates uninitialized constant-sized pages of memory.
 */
#  define AH_CONF_PALLOC() AH_CONF_MALLOC(AH_CONF_PSIZE)
# endif
#endif

#ifndef AH_CONF_PFREE
/**
 * Function used to free allocate pages, as described in alloc.h.
 *
 * Releases memory allocated via the function specified by @c AH_CONF_PALLOC.
 */
# define AH_CONF_PFREE AH_CONF_FREE
#endif

#ifndef AH_CONF_PSIZE
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_PSIZE 1024u
# else
/**
 * The size of a page allocator page, in bytes.
 *
 * The function specified via @c AH_CONF_PALLOC must return chunks of memory of
 * at least this size.
 */
#  define AH_CONF_PSIZE 8192u
# endif
#endif

#ifndef AH_CONF_REALLOC
/**
 * Used C99 @c realloc() implementation.
 *
 * Reallocates previously allocated chunks of memory.
 */
# define AH_CONF_REALLOC realloc
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_URING_DEFAULT_CAPACITY
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_URING_DEFAULT_CAPACITY 32u
# else
/**
 * [io_uring] Default ah_loop @c capacity for platforms relying on the Linux
 * io_uring API.
 *
 * A higher value @e may lead to higher event loop throughput.
 */
#  define AH_CONF_URING_DEFAULT_CAPACITY 1024u
# endif
#endif

#ifdef AH_I_CONF_INCLUDE_STDLIB_H
# include <stdlib.h>
#endif

#endif
