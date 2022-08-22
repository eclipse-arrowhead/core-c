// SPDX-License-Identifier: EPL-2.0

#ifndef AH_RW_H_
#define AH_RW_H_

/**
 * Memory reader/writer.
 * @file
 *
 * This file provides ah_rw, or the @e Reader/Writer (R/W), which is a set of
 * pointers that points into a block of memory as follows:
 * @code
 *                          r           w                       e
 *                          |           |                       |
 *                          V           V                       V
 *              +---+---+---+---+---+---+---+---+---+---+---+---+
 * Memory block | 1 | 7 | 3 | 2 | 4 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
 *              +---+---+---+---+---+---+---+---+---+---+---+---+
 *                           :.........: :.....................:
 *                                :                 :
 *                         Readable bytes     Writable bytes
 * @endcode
 *
 * The following invariants must always be satisfied for every initialized
 * reader/writer:
 * <ol>
 *   <li>The @c r pointer must be less than or equal to @c w.
 *   <li>The @c w pointer must be less than or equal to @c e.
 *   <li>All of @c r, @c w and @c e must point into or to the first byte right
 *       after the same block of memory.
 * </ol>
 *
 * The most straightforward way to ensure that the invariants remain true for a
 * given ah_rw instance is to initialize and update it only through the
 * functions listed in this header.
 */

#include "defs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * An (R/W) pointer set.
 *
 * Please refer to the documentation for rw.h for a more detailed description
 * of this data structure.
 *
 * @see rw.h
 */
struct ah_rw {
    uint8_t* r; /**< Read pointer. */
    uint8_t* w; /**< Write pointer. */
    uint8_t* e; /**< End pointer. */
};

/**
 * Creates new writable R/W from @a base and @a size.
 *
 * The R/W created by this function will treat @a base as uninitialized memory
 * and require that it is written to before it can be read.
 *
 * @param base Pointer to first byte of a writable memory region.
 * @param size The number of writable bytes referred to by @a base.
 * @return Created R/W.
 *
 * @warning The created ah_rw becomes invalid if @a base is @c NULL and @a size
 *          is positive.
 */
ah_extern ah_rw_t ah_rw_from_writable(void* base, size_t size);

/**
 * Creates new writable R/W from @a buf.
 *
 * The R/W created by this function will treat the memory referred to by @a buf
 * as uninitialized memory and require that it is written to before it can be
 * read.
 *
 * @param buf Pointer to a sized memory reference.
 * @return Created R/W.
 *
 * @note Returns a zeroed ah_rw if @a buf is @c NULL.
 * @warning If @a buf is invalid, also the created ah_rw becomes invalid.
 */
ah_extern ah_rw_t ah_rw_from_writable_buf(ah_buf_t* buf);

/**
 * Creates new readable R/W from @a base and @a size.
 *
 * The R/W created by this function will treat @a base as initialized memory
 * and only allow for it to be read.
 *
 * @param base Pointer to first byte of a readable memory region.
 * @param size The number of readable bytes referred to by @a base.
 * @return Created R/W.
 *
 * @warning The created ah_rw becomes invalid if @a base is @c NULL and @a size
 *          is positive.
 */
ah_extern ah_rw_t ah_rw_from_readable(const void* base, size_t size);

/**
 * Creates new readable R/W from @a buf.
 *
 * The R/W created by this function will treat the memory referred to by @a buf
 * as initialized memory and only allow for it to be read.
 *
 * @param buf Pointer to a sized memory reference.
 * @return Created R/W.
 *
 * @note Returns a zeroed ah_rw if @a buf is @c NULL.
 * @warning If @a buf is invalid, also the created ah_rw becomes invalid.
 */
ah_extern ah_rw_t ah_rw_from_readable_buf(const ah_buf_t* buf);

/**
 * Creates a new ah_buf from the readable range of @a rw.
 *
 * @param rw Pointer to R/W.
 * @return Buffer representing the readable portion of the memory referred to
 *         by @a rw.
 *
 * @note Returns a zeroed ah_buf if @a rw is @c NULL.
 * @warning If @a rw is invalid, the created ah_buf may become invalid.
 */
ah_extern ah_buf_t ah_rw_get_readable_as_buf(const ah_rw_t* rw);

/**
 * Calculates the size of the readable range of @a rw.
 *
 * @param rw Pointer to R/W.
 * @return Number of bytes part of the readable memory referred to by @a rw.
 *
 * @note Returns @c 0 if @a rw is @c NULL.
 */
ah_extern size_t ah_rw_get_readable_size(const ah_rw_t* rw);

/**
 * Creates a new ah_buf from the writable range of @a rw.
 *
 * @param rw Pointer to R/W.
 * @return Buffer representing the writable portion of the memory referred to
 *         by @a rw.
 *
 * @note Returns a zeroed ah_buf if @a rw is @c NULL.
 * @warning If @a rw is invalid, the created ah_buf may become invalid.
 */
ah_extern ah_buf_t ah_rw_get_writable_as_buf(const ah_rw_t* rw);

/**
 * Calculates the size of the writable range of @a rw.
 *
 * @param rw Pointer to R/W.
 * @return Number of bytes part of the writable memory referred to by @a rw.
 *
 * @note Returns @c 0 if @a rw is @c NULL.
 */
ah_extern size_t ah_rw_get_writable_size(const ah_rw_t* rw);

/**
 * Checks if the readable section of @a rw has a non-zero size.
 *
 * @param rw Pointer to R/W.
 * @return @c true only if @a rw refers to a non-zero number of readable bytes.
 *
 * @note Returns @c false if @a rw is @c NULL.
 */
ah_extern bool ah_rw_is_readable(const ah_rw_t* rw);

/**
 * Checks if the writable section of @a rw has a non-zero size.
 *
 * @param rw Pointer to R/W.
 * @return @c true only if @a rw refers to a non-zero number of writable bytes.
 *
 * @note Returns @c false if @a rw is @c NULL.
 */
ah_extern bool ah_rw_is_writable(const ah_rw_t* rw);

/**
 * Reads one byte from @a src and writes it to @a dst.
 *
 * @param src Pointer to source R/W.
 * @param dst Pointer to destination R/W.
 * @return @c true only if exactly one byte could be read from @a src and be
 *         written to @a dst.
 *
 * @note Does nothing and returns @c false if either of @a src or @a dst is
 *       @c NULL, if @a src has no readable byte, or if @a dst hos no writable
 *       byte.
 */
ah_extern bool ah_rw_copy1(ah_rw_t* src, ah_rw_t* dst);

/**
 * Reads @a n bytes from @a src and writes them to @a dst.
 *
 * @param src Pointer to source R/W.
 * @param dst Pointer to destination R/W.
 * @param n   Number of bytes to copy from @a src to @a dst.
 * @return @c true only if exactly @a n bytes could be read from @a src and be
 *         written to @a dst.
 *
 * @note Does nothing and returns @c false if either of @a src or @a dst is
 *       @c NULL, if less than @a n bytes can be read from @a src, or if less
 *       than @a n bytes can be written to @a dst.
 */
ah_extern bool ah_rw_copyn(ah_rw_t* src, ah_rw_t* dst, size_t n);

/**
 * Reads one byte from @a rw and writes it to @a dst.
 *
 * @param rw  Pointer to source R/W.
 * @param dst Pointer to byte receiver.
 * @return @c true only if exactly one byte could be read from @a rw and be
 *         written to @a dst.
 *
 * @note Does nothing and returns @c false if either of @a rw or @a dst is
 *       @c NULL, or if @a rw has no readable byte.
 */
ah_extern bool ah_rw_peek1(ah_rw_t* rw, uint8_t* dst);

/**
 * Reads @a n bytes from @a src and writes them to @a dst.
 *
 * @param rw  Pointer to source R/W.
 * @param dst Pointer to beginning of memory region that will receive copy of
 *            the read bytes.
 * @param n   Number of bytes to read from @a rw and write to @a dst.
 * @return @c true only if exactly @a n bytes could be read from @a rw and be
 *         written to @a dst.
 *
 * @note Does nothing and returns @c false if either of @a src or @a dst is
 *       @c NULL, or if @a rw has less than @a n readable bytes.
 */
ah_extern bool ah_rw_peekn(ah_rw_t* rw, uint8_t* dst, size_t n);

/**
 * Reads one byte from @a rw, writes it to @a dst and advances the read
 *        pointer of @a rw one byte.
 *
 * @param rw  Pointer to source R/W.
 * @param dst Pointer to byte receiver.
 * @return @c true only if exactly one byte could be read from @a rw and be
 *         written to @a dst.
 *
 * @note Does nothing and returns @c false if @a rw is @c NULL or @a rw has no
 *       more readable bytes.
 */
ah_extern bool ah_rw_read1(ah_rw_t* rw, uint8_t* dst);

/**
 * Reads @a n bytes from @a src, writes them to @a dst and advances the
 *        read pointer of @a rw @a n bytes.
 *
 * @param rw  Pointer to source R/W.
 * @param dst Pointer to beginning of memory region that will receive copy of
 *            the read bytes.
 * @param n   Number of bytes to read from @a src and write to @a dst.
 * @return @c true only if exactly @a n bytes could be read from @a src and be
 *         written to @a dst.
 *
 * @note Does nothing and returns @c false if either of @a src or @a dst is
 *       @c NULL, or if less than @a n bytes can be read from @a rw.
 */
ah_extern bool ah_rw_readn(ah_rw_t* rw, uint8_t* dst, size_t n);

/**
 * Advances the read pointer of @a rw one byte.
 *
 * @param rw Pointer to R/W.
 * @return @c true only if exactly one byte could be read and discarded from
 *         @a src.
 *
 * @note Does nothing and returns @c false if @a src is @c NULL. or if @a rw
 *       has no more readable bytes.
 */
ah_extern bool ah_rw_skip1(ah_rw_t* rw);

/**
 * Advances the read pointer of @a rw @a n bytes.
 *
 * @param rw Pointer to R/W.
 * @param n  Number of bytes to skip.
 * @return @c true only if exactly @a n bytes could be read and discarded from
 *         @a src.
 *
 * @note Does nothing and returns @c false if @a rw is @c NULL or if @a n is
 *       larger than the number of readable bytes in @a rw.
 */
ah_extern bool ah_rw_skipn(ah_rw_t* rw, size_t n);

/**
 * Advances the read pointer of @a rw to its write pointer, effectively
 *        discarding all currently readable bytes.
 *
 * @param rw Pointer to R/W.
 *
 * @note Does nothing if @a rw is @c NULL.
 */
ah_extern void ah_rw_skip_all(ah_rw_t* rw);

/**
 * Writes @a byte to @a rw and advances its write pointer one byte.
 *
 * @param rw   Pointer to destination R/W.
 * @param byte Byte to write.
 * @return @c true only if @a byte could be written to @a rw.
 *
 * @note Does nothing and returns @c false if @a rw is @c NULL or if @a rw has
 *       no more writable bytes.
 */
ah_extern bool ah_rw_write1(ah_rw_t* rw, uint8_t byte);

/**
 * Writes @a n bytes from @a src to @a rw and advances its write pointer
 *        @a n bytes.
 *
 * @param rw  Pointer to destination R/W.
 * @param src Pointer to beginning of memory region that contains the bytes
 *            that are to be written to @a rw.
 * @param n   Number of bytes to write.
 * @return @c true only if @a n bytes from @a src could be written to @a rw.
 *
 * @note Does nothing and returns @c false if either of @a rw or @a src is
 *       @c NULL, or if @a n is larger than the number of writable bytes in
 *       @a rw.
 */
ah_extern bool ah_rw_writen(ah_rw_t* rw, uint8_t* src, size_t n);

/**
 * Advances the write pointer of @a rw one byte.
 *
 * @param rw Pointer to R/W.
 * @return @c true only if the write pointer of @a rw could be advanced one
 *         byte.
 *
 * @note Does nothing and returns @c false if @a rw @c NULL or if there are no
 *       remaining writable bytes.
 * @warning This function is only safe to use when it is known that the next
 *          writable byte of @a rw is initialized.
 */
ah_extern bool ah_rw_juke1(ah_rw_t* rw);

/**
 * Advances the write pointer of @a rw @a n bytes.
 *
 * @param rw Pointer to R/W.
 * @param n  Number of bytes to skip.
 * @return @c true only if the write pointer of @a rw could be advanced @a n
 *         bytes.
 *
 * @note Does nothing and returns @c false if @a rw @c NULL or if @a n is
 *       larger than the remaining number of writable bytes in @a rw.
 * @warning This function is only safe to use when it is known that the next
 *          @a n writable bytes of @a rw are initialized.
 */
ah_extern bool ah_rw_juken(ah_rw_t* rw, size_t n);

#endif
