// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

/**
 * @file
 * Platform buffer representation.
 *
 * This file provides a simple data structure, ah_buf, that is used to refer to
 * contiguous chunks of memory. The data structure may be used internally by
 * various platform APIs, for which reason its layout and fields may vary
 * across platforms.
 */
#include "internal/_buf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** The largest size, in bytes, that can be represented by an ah_buf. */
#define AH_BUF_SIZE_MAX AH_I_BUF_SIZE_MAX

/**
 * A sized reference to a contiguous chunk of memory.
 *
 * @warning The order of its fields, as well as the type of its @a size
 *          field, may vary across supported platforms.
 */
struct ah_buf {
#if AH_IS_WIN32
    ULONG size; // Guaranteed to be of a size smaller than or equal to size_t.
    uint8_t* base;
#else
    /** Pointer to buffer memory. */
    uint8_t* base;

    /** Size, in bytes, of memory referred to by @a base. */
    size_t size;
#endif
};

/**
 * Safely initializes @a buf with @a base pointer and @a size.
 *
 * @param buf  Pointer to initialized buffer.
 * @param base Pointer to chunk of memory.
 * @param size Size of chunk of memory referred to by @a base.
 * @return One of the following error codes: <ul>
 *   <li><b>AH_ENONE</b>             - If initialization was successful.
 *   <li><b>AH_EINVAL</b>            - @a buf is @c NULL or @a base is @c NULL and @a size is
 *                                     positive.
 *   <li><b>AH_EOVERFLOW [Win32]</b> - @a size is larger than @c AH_BUF_SIZE_MAX.
 * </ul>
 */
ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size);

/**
 * Creates new ah_buf from given @a base pointer and 32-bit @a size.
 *
 * @param base Pointer to chunk of memory.
 * @param size Size of chunk of memory referred to by @a base.
 * @return Created buffer.
 *
 * @note In contrast to ah_buf_init(), this function never fails. This is made
 * possible by @a size always being a 32-bit type, which is small enough to be
 * representable by every ah_buf.
 */
ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size);

/**
 * Checks if @a buf has a @c NULL @c base or a @c size being @c 0.
 *
 * @param buf Pointer to checked buffer.
 * @return @c true, only if @a buf has a @c NULL @c base or @c a @c size being
 *         @c 0.
 */
ah_extern bool ah_buf_is_empty(const ah_buf_t* buf);

#endif
