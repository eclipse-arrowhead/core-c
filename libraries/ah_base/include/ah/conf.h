// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_CONF_H_
#define AH_CONF_H_

#if !defined(AH_CONF_INCLUDE) && defined(__has_include) && __has_include("ah-base-conf-custom.h")
# define AH_CONF_INCLUDE "ah-base-conf-custom.h"
#endif

#ifdef AH_CONF_INCLUDE
# include AH_CONF_INCLUDE
#endif

#if !defined(AH_CONF_IS_CONSTRAINED) && defined(__arm__) && !defined(__aarch64__)
# define AH_CONF_IS_CONSTRAINED 1
#endif
#ifndef AH_CONF_IS_CONSTRAINED
# define AH_CONF_IS_CONSTRAINED 0
#endif

#ifndef AH_CONF_CALLOC
# define AH_CONF_CALLOC calloc
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_FREE
# define AH_CONF_FREE free
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_IOCP_COMPLETION_ENTRY_BUFFER_SIZE
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_IOCP_COMPLETION_ENTRY_BUFFER_SIZE 4u
# else
#  define AH_CONF_IOCP_COMPLETION_ENTRY_BUFFER_SIZE 128u
# endif
#endif

#ifndef AH_CONF_IOCP_DEFAULT_CAPACITY
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_IOCP_DEFAULT_CAPACITY 32u
# else
#  define AH_CONF_IOCP_DEFAULT_CAPACITY 1024u
# endif
#endif

#ifndef AH_CONF_KQUEUE_DEFAULT_CAPACITY
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_KQUEUE_DEFAULT_CAPACITY 32u
# else
#  define AH_CONF_KQUEUE_DEFAULT_CAPACITY 1024u
# endif
#endif

#ifndef AH_CONF_MALLOC
# define AH_CONF_MALLOC malloc
# ifndef AH_I_CONF_INCLUDE_STDLIB_H
#  define AH_I_CONF_INCLUDE_STDLIB_H
# endif
#endif

#ifndef AH_CONF_PALLOC
# ifndef NDEBUG
#  define AH_CONF_PALLOC() AH_CONF_CALLOC(1u, AH_CONF_PSIZE)
# else
#  define AH_CONF_PALLOC() AH_CONF_MALLOC(AH_CONF_PSIZE)
# endif
#endif

#ifndef AH_CONF_PFREE
# define AH_CONF_PFREE AH_CONF_FREE
#endif

#ifndef AH_CONF_PSIZE
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_PSIZE 1024u
# else
#  define AH_CONF_PSIZE 8192u
# endif
#endif

#ifndef AH_CONF_URING_DEFAULT_CAPACITY
# if AH_CONF_IS_CONSTRAINED
#  define AH_CONF_URING_DEFAULT_CAPACITY 32u
# else
#  define AH_CONF_URING_DEFAULT_CAPACITY 1024u
# endif
#endif

#ifdef AH_I_CONF_INCLUDE_STDLIB_H
# include <stdlib.h>
#endif

#endif
