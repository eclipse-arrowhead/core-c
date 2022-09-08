// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UTF8_H_
#define AH_UTF8_H_

/**
 * @file
 * UTF-8 utilities.
 *
 * This file provides functions for dealing with the UTF-8 character encoding.
 *
 * @see https://rfc-editor.org/rfc/rfc3629
 */

#include "defs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Validates UTF-8 text in @a src.
 *
 * A UTF-8 text is considered valid if it only contains complete UTF-8 sequences
 * and none of those sequences encodes an invalid codepoint.
 *
 * @param src  Pointer to string containing UTF-8 encoded text.
 * @param size Size of @a src, in bytes.
 * @return @c true only if @a src contains a valid UTF-8 encoded text. @c false
 *         otherwise.
 */
ah_extern bool ah_utf8_validate(const char* src, size_t size);

/**
 * Writes the UTF-8 sequence representing @a codepoint to @a dst.
 *
 * If the operation is successful, the value pointed at by @a dst_length is
 * updated to reflect the final length of the string actually written to @a dst.
 *
 * @param codepoint  Unicode codepoint.
 * @param dst        Pointer to receiver of UTF-8 sequence.
 * @param dst_length Pointer to size of @a dst, in bytes.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - Operation successful.
 *   <li>@ref AH_EINVAL    - @a dst is @c NULL or @a size is @c 0.
 *   <li>@ref AH_EINVAL    - @a codepoint is invalid. More specifically, it is
 *                           either between 0xD800 and 0xDFFF or above 0x10FFFF.
 *                           The former range is reserved for constructing
 *                           surrogate pairs with UTF-16, while the latter range
 *                           is simply not defined for UTF-8.
 *   <li>@ref AH_EOVERFLOW - UTF-8 sequence too long to fit in @a dst.
 * </ul>
 *
 * @note As per RFC3629, no UTF-8 sequence will ever be longer than 4 bytes,
 *       even though sequences of up to 6 bytes are theoretically possible.
 *
 * @see https://rfc-editor.org/rfc/rfc3629
 */
ah_extern ah_err_t ah_utf8_from_codepoint(uint32_t codepoint, char* dst, size_t* dst_length);

#endif
