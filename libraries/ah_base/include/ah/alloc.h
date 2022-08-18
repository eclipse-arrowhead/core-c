// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ALLOC_H_
#define AH_ALLOC_H_

/// \brief Dynamic memory allocation.
/// \file
///
/// This file most significantly provides function for allocating and freeing
/// dynamic memory. If provides analogies to the malloc(), calloc() and free()
/// functions of the C99 standard library, as well as functions for allocating
/// and freeing \e pages of memory. A \e page is a contiguous chunk of
/// \c AH_PSIZE bytes, aligned to a memory boundary deemed suitable by the
/// library implementation.
///
/// In contrast to the C99 allocator, the page allocator is relatively simple to
/// implement such that it effectively avoids memory fragmentation. As all pages
/// are of the same size, those pages can be allocated and freed relatively
/// fast. The page allocator is used, when possible, by the Arrowhead Core C
/// libraries.
///
/// \note What functions are concretely provided can be configured as described
/// in conf.h.

#include "conf.h"

/// \brief The size, in bytes, of the memory pages returned by ah_palloc().
#define AH_PSIZE AH_CONF_PSIZE

/// \brief Allocates and zeroes an array of \a n elements, each being \a size
/// bytes large.
///
/// \param n    Number of elements to allocate.
/// \param size Size, in bytes, of each element.
/// \return A zeroed chunk of memory, or \c NULL if no sufficiently large chunk
///         can be allocated.
#define ah_calloc(n, size) AH_CONF_CALLOC((n), (size))

/// \brief Releases referenced memory block, potentially making it possible for
/// the allocator to use it again.
///
/// \param ptr Pointer previously acquired from ah_calloc() or ah_malloc().
///
/// \warning It is an error to provide a pointer returned by ah_palloc(), or any
///          other allocation function, to this function.
#define ah_free(ptr) AH_CONF_FREE((ptr))

/// \brief Allocates a contiguous chunk of at least \a size bytes of memory.
///
/// \param size Size, in bytes, of chunk to allocate.
/// \return An uninitialized chunk of memory, or \c NULL if no sufficiently
///         large chunk can be allocated.
#define ah_malloc(size) AH_CONF_MALLOC((size))

/// \brief Allocates a \e page of memory, guaranteed to be at least AH_PSIZE
/// bytes large.
///
/// \return An uninitialized chunk of memory, or \c NULL if no sufficiently
///         large chunk can be allocated.
#define ah_palloc() AH_CONF_PALLOC()

/// \brief Releases referenced memory page, potentially making it possible for
/// the page allocator to use it again.
///
/// \param page Pointer previously acquired from ah_palloc().
///
/// \warning It is an error to provide a pointer returned by ah_calloc(),
///          ah_malloc() or any other allocation function, to this function.
#define ah_pfree(page) AH_CONF_PFREE((page))

/// \brief Reallocates memory chunk associated with \a ptr.
///
/// Conceptually, this function allocates a new memory chunk of \a size bytes,
/// copies over the contents of the \a ptr buffer (or as much of it as fits in
/// the new chunk), and then frees the memory associated with \a ptr. If \a size
/// is larger than the previous size of the \a ptr chunk, the additional memory
/// is uninitialized. Practically, this function may expand or contract the
/// \a ptr chunk in place, or do something else with the same observable result.
///
/// \param ptr  Pointer previously acquired from ah_calloc(), ah_malloc() or
///             ah_realloc().
/// \param size Desired size, in bytes, of chunk after reallocation.
/// \return A chunk of memory of at least \a size bytes that contain the
///         contents previously associated with \a ptr. \c NULL if the
///         reallocation failed, in which case the chunk of \a ptr remains
///         unmodified.
///
/// \warning If \a size is \c 0 and \a ptr is not \c NULL, the result \e may be
///          a pointer to a new buffer with size \a 0 being returned or \c NULL
///          being returned.
#define ah_realloc(ptr, size) AH_CONF_REALLOC((ptr), (size))

#endif
