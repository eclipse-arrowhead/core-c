// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ALLOC_H_
#define AH_ALLOC_H_

/**
 * @file
 * Dynamic memory allocation.
 *
 * This file most significantly provides function for allocating and freeing
 * dynamic memory. It provides two allocators, a <em>page allocator</em> and the
 * <em>C99 allocator</em>. The implementations of the allocators can be changed
 * by specifying their replacements as directed in conf.h.
 *
 * <h3>Page Allocator</h3>
 *
 * A @e page is a contiguous chunk of @ref AH_PSIZE bytes, aligned to a memory
 * boundary deemed suitable by the current library platform implementation. The
 * page allocator provides and recycles such pages via the ah_palloc() and
 * ah_pfree() functions.
 *
 * In contrast to the C99 allocator, the page allocator is relatively simple to
 * implement. As every page is of the exact same size, the allocator may return
 * any of them when new memory is requested. An implementation of a page
 * allocator may, for example, use a predefined set of chunks and keep track of
 * which of them are available for allocation via a single linked list.
 *
 * The page allocator is used, when possible, by the Arrowhead Core C libraries.
 *
 * <h3>C99 Allocator</h3>
 *
 * The C99 allocator concretely consists of the @c malloc(), @c calloc(),
 * @c realloc() and @c free() functions. However, implementing these in a manner
 * that is both space-efficient and performant can be difficult, and especially
 * so on embedded platforms. As a consequence, this library, and most other
 * official Arrowhead C libraries, are designed to work even when the
 * implementations of these functions are very limited. More specifically, an
 * acceptable C99 allocator implementation
 * <ol>
 *   <li>returns valid pointers when allocating new memory (if the requested number of bytes of heap
 *       memory are available),
 *   <li>fails every attempt to reallocate memory (i.e. the first argument to @c realloc() is not
 *       @c NULL), and
 *   <li>ignores any attempt to free memory.
 * </ol>
 * All library functionality that relies on being able to continually allocate
 * and release memory must use the page allocator or be able to operate without
 * using the C99 allocator at all.
 *
 * @note Please refer to conf.h for more details on how to configure what C99
 *       allocator function implementations are to be used.
 */

#include "conf.h"

/** Size, in bytes, of the memory pages returned by ah_palloc(). */
#define AH_PSIZE AH_CONF_PSIZE

/**
 * Allocates and zeroes an array of @a n elements, each being @a size bytes
 * large.
 *
 * If @a n multiplied by @a size overflows, this function must allocate no
 * memory and return @c NULL.
 *
 * @param n    Number of elements to allocate.
 * @param size Size, in bytes, of each element.
 * @return A zeroed chunk of memory, or @c NULL if no sufficiently large chunk
 *         can be allocated.
 */
#define ah_calloc(n, size) AH_CONF_CALLOC((n), (size))

/**
 * Releases referenced memory block, potentially making it possible for the
 * allocator to use it again.
 *
 * @param ptr Pointer previously acquired from ah_calloc(), ah_malloc() or
 *            ah_realloc().
 *
 * @warning It is an error to provide a pointer returned by ah_palloc(), or any
 *          other allocation function than those listed above, to this function.
 */
#define ah_free(ptr) AH_CONF_FREE((ptr))

/**
 * Allocates a contiguous chunk of at least @a size bytes of memory.
 *
 * @param size Size, in bytes, of chunk to allocate.
 * @return An uninitialized chunk of memory, or @c NULL if no sufficiently
 *         large chunk can be allocated.
 */
#define ah_malloc(size) AH_CONF_MALLOC((size))

/**
 * Allocates a @e page of memory, guaranteed to be at least @ref AH_PSIZE bytes
 * large.
 *
 * The value of @ref AH_PSIZE can be adjusted by modifying @c AH_CONF_PSIZE, more
 * of which you can read in conf.h.
 *
 * @return An uninitialized chunk of memory, or @c NULL if no sufficiently
 *         large chunk can be allocated.
 */
#define ah_palloc() AH_CONF_PALLOC()

/**
 * Releases referenced memory page, making it possible for the page allocator to
 * use it again.
 *
 * @param page Pointer previously acquired from ah_palloc().
 *
 * @warning It is an error to provide a pointer returned by ah_calloc(),
 *          ah_malloc() or any other allocation function than ah_palloc(), to
 *          this function.
 */
#define ah_pfree(page) AH_CONF_PFREE((page))

/**
 * Reallocates memory chunk associated with @a ptr.
 *
 * Conceptually, this function allocates a new memory chunk of @a size bytes,
 * copies over the contents of the @a ptr buffer (or as much of it as fits in
 * the new chunk), and then frees the memory associated with @a ptr. If @a size
 * is larger than the previous size of the @a ptr chunk, the additional memory
 * is uninitialized. Practically, this function may expand or contract the
 * @a ptr chunk in place, or do something else with the same observable result.
 *
 * @param ptr  Pointer previously acquired from ah_calloc(), ah_malloc() or
 *             ah_realloc().
 * @param size Desired size, in bytes, of chunk after reallocation.
 * @return A chunk of memory of at least @a size bytes that contain the
 *         contents previously associated with @a ptr. @c NULL if the
 *         reallocation failed, in which case the chunk of @a ptr remains
 *         unmodified.
 *
 * @note If @a size <em>is not</em> @c 0 and @a ptr @e is @c NULL, this function
 *       will behave exactly as a call to ah_malloc() with the same size.
 *
 * @warning If @a size <em>is not</em> @c 0 and @a ptr <em>is not</em> @c NULL,
 *          this function may, if implemented so, always return @c NULL.
 *
 * @warning If @a size @e is @c 0 and @a ptr <em>is not</em> @c NULL, the
 *          function may either return a pointer to a memory chunk with size
 *          @c 0 or return @c NULL.
 *
 * @warning If @a size @e is @c 0 and @a ptr @e is @c NULL, the result of
 *          calling this function is undefined.
 */
#define ah_realloc(ptr, size) AH_CONF_REALLOC((ptr), (size))

#endif
