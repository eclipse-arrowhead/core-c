// SPDX-License-Identifier: EPL-2.0

#ifndef AH_JSON_H_
#define AH_JSON_H_

#include <ah/buf.h>
#include <ah/defs.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/**
 * @file
 * JavaScript Object Notation (JSON) utilities.
 *
 * As a data interchange format, JSON is mainly dealt with directly in two
 * cases: (1) when constructing JSON representations and (2) when interpreting
 * JSON representations. Here, we primarily provide utilities for interpreting
 * JSON. That being said, we will consider how to accomplish these two
 * activities using only the C99 standard library and this library. First,
 * however, we will consider what kinds of data structures JSON can represent.
 *
 * <h3>JSON Representation</h3>
 *
 * A json representation, or @e Value, can take any out of seven distinct types,
 * outlined in the following table:
 *
 * <table>
 *   <caption id="json-types">JSON Value Types</caption>
 *   <tr>
 *     <th>Name
 *     <th>Description
 *     <th>Example
 *   <tr>
 *     <td>@e Object
 *     <td><code>'{'</code>, a sequence of <code>String ':' Value</code> pairs separated by
 *         <code>','</code>, and <code>'}'</code>.
 *     <td><code>{"celsius": 26.3}</code>
 *   <tr>
 *     <td>@e Array
 *     <td><code>'['</code>, a sequence of <code>Value</code> elements separated by
 *         <code>','</code>, and <code>']'</code>.
 *     <td><code>[1, 2, 3]</code>
 *   <tr>
 *     <td>@e String
 *     <td>A UTF-8 text that may contain escape sequences.
 *     <td><code>"Arrowhead"</code>
 *   <tr>
 *     <td>@e Number
 *     <td>A decimal number with an optional fraction and an optional exponent.
 *     <td><code>0.031415e2</code>
 *   <tr>
 *     <td>@e True
 *     <td>Boolean true, represented by the string @c true.
 *     <td><code>true</code>
 *   <tr>
 *     <td>@e False
 *     <td>Boolean false, represented by the string @c false.
 *     <td><code>false</code>
 *   <tr>
 *     <td>@e Null
 *     <td>The absence of a meaningful value, represented by the string @c null.
 *     <td><code>null</code>
 * </table>
 *
 * Objects and arrays are <em>data structures</em> in the sense that they can
 * contain, or @e structure, other values. The other types can be considered
 * primitives, by which we simply mean that they do not directly contain other
 * values. Using objects and arrays, arbitrarily complex data structures can be
 * constructed, such as
 * <code>{"id": 1937321, "colors": [{"r": 0, "g": 0, "b": 255}, "red"]}</code>.
 *
 * @note JSON lacks a type for representing binary strings, and it cannot
 *       directly associate metadata, such as type information, with objects or
 *       other types. That being said, there are ways to circumvent these
 *       shortcomings, such as by <a href="https://www.rfc-editor.org/rfc/rfc4648.html">Base64-encoding</a>
 *       binary data and using custom schemes for representing metadata.
 *
 * <h3>JSON Construction</h3>
 *
 * From the perspective of constructing JSON objects, this library most
 * significantly provides the ah_json_str_escape() function, which takes an
 * arbitrary C string and escapes any characters that are not allowed to occur
 * unescaped in a JSON document. The C99 standard library provides complementary
 * functions for converting numbers into strings, such as strtod() and
 * strtoul(), all of which produce numbers compatible with the JSON standard.
 *
 * To produce JSON objects and arrays, the snprintf() function can be used, as
 * in the below example:
 *
 * @code{.c}
 * #include <stddef.h>
 * #include <stdio.h>
 *
 * struct Temperature {
 *   char sensor_name[32];
 *   float kelvin;
 * };
 *
 * int main(void) {
 *   char buf[128u];
 *
 *   // Data to encode.
 *   struct Temperature temp = {
 *       .sensor_name = "aa-xx-142b", // We "know" this string will not need to be escaped.
 *       .kelvin = 296.55f,
 *   };
 *
 *   // Encode.
 *   int res = snprintf(buf, sizeof(buf), "{\"sensor_name\":\"%s\",\"kelvin\":%f}",
 *       temp.sensor_name, temp.kelvin);
 *
 *   if (res < 0) {
 *       perror(NULL);
 *       return 1;
 *   }
 *
 *   if (res > sizeof(buf)) {
 *      fprintf(stderr, "result too large");
 *      return 1;
 *   }
 *
 *   // `buf` now contains a JSON object of size `res`.
 *
 *   printf("%.*s\n", res, buf); // Prints `{"sensor_name":"aa-xx-142b","kelvin":296.55}`.
 *
 *   return 0;
 * }
 * @endcode
 *
 * By using snprintf() and other functions in clever ways, you can produce JSON
 * data relatively efficiently and correctly.
 *
 * <h3>JSON Interpretation</h3>
 *
 * @note Refer to the ECMA-404 standard for a formally correct syntax
 *       description. The standard to is linked further down.
 *
 * @see https://www.ecma-international.org/publications-and-standards/standards/ecma-404/
 */

// JSON numbers are compatible with snprintf, sscanf, strfromd, strtod, etc. as
// long as the set locale uses "." as radix character (which the default "C"
// locale does). You may use those functions to read and write JSON numbers.

#ifdef AH_DOXYGEN

/**
 * The maximum size, in bytes, of individual JSON tokens produced by
 * ah_json_parse().
 */
# define AH_JSON_LENGTH_MAX

/**
 * The maximum tree depth supported for input strings parsed by ah_json_parse().
 */
# define AH_JSON_LEVEL_MAX

#endif

/**
 * @name JSON Value Types
 *
 * Used to indicate the concrete types of ah_json_val instances.
 *
 * @{
 */
#define AH_JSON_TYPE_ERROR  0u /**< Unexpected input character. */
#define AH_JSON_TYPE_OBJECT 1u
#define AH_JSON_TYPE_ARRAY  2u
#define AH_JSON_TYPE_STRING 3u
#define AH_JSON_TYPE_NUMBER 4u
#define AH_JSON_TYPE_TRUE   5u
#define AH_JSON_TYPE_FALSE  6u
#define AH_JSON_TYPE_NULL   7u
/** @} */

typedef struct ah_json_buf ah_json_buf_t;
typedef struct ah_json_val ah_json_val_t;

/**
 * JSON token buffer.
 *
 * Stores the result of parsing a JSON input string.
 */
struct ah_json_buf {
    /** The maximum number values that can currently be stored in @a values. */
    size_t capacity;

    /** The current number of values in @a values. */
    size_t length;

    /** Pointer to the base of an array of JSON values. */
    ah_json_val_t* values;
};

/**
 * JSON value, concretely represented as a token.
 *
 * Represents a single value part of some JSON input.
 */
struct ah_json_val {
    /**
     * Pointer to position within JSON input where the current value begins.
     *
     * If @a type is @c AH_JSON_TYPE_OBJECT or @c AH_JSON_TYPE_ARRAY, this
     * pointer is guaranteed to point directly at a @c { or @c [ character,
     * respectively. If @a type has any other value, the length of this string
     * is indicated by @a length.
     */
    const char* base;

#if UINTPTR_MAX == UINT32_MAX && !defined(AH_DOXYGEN)
# define AH_JSON_LENGTH_MAX (UINT32_C(0x001FFFFF))
# define AH_JSON_LEVEL_MAX  (0xFF)

    uint32_t type   : 3;
    uint32_t level  : 8;
    uint32_t length : 21;

#elif UINTPTR_MAX == UINT64_MAX && !defined(AH_DOXYGEN)
# define AH_JSON_LENGTH_MAX (UINT64_C(0x0000FFFFFFFFFFFF))
# define AH_JSON_LEVEL_MAX  (0x1FFF)

    uint64_t type   : 3;
    uint64_t level  : 13;
    uint64_t length : 48;

#elif !defined(AH_DOXYGEN)
# define AH_JSON_LENGTH_MAX (UINT32_MAX)
# define AH_JSON_LEVEL_MAX  (UINT16_MAX)

    uint16_t type;
    uint16_t level;
    uint32_t length;

#else

    /**
     * The concrete JSON type of this value.
     *
     * @note The concrete type used to represent the current type varies across
     *       supported platforms. That type is, however, guaranteed to be able
     *       to hold the identifiers for all 8 JSON types, which includes the
     *       custom @c AH_JSON_TYPE_ERROR identifier.
     */
    uintX_t type;

    /**
     * The tree depth at which this value is located in its input string.
     *
     * To better understand what a level is, consider the following JSON object:
     *
     * @code{.json}
     *   {
     *     "a": [1, 2, 3],
     *     "b": null
     *   }
     * @endcode
     *
     * Its root object, whose start is indicated by @c {, is located at level
     * @c 0. Its two keys, @c "a" and @c "b", and their values, the array
     * indicated by <code>[</code> and @c null, are at level @c 1. The numbers
     * @c 1, @c 2 and @c 3, all inside the array, are all at level @c 2.
     *
     * When iterating through tokens, you can reliably determine when, for
     * example, an array ends, by looking for a change in the current level.
     *
     * @note The concrete type used to represent the current level varies across
     *       supported platforms. That type is, however, guaranteed to be able
     *       to hold any integer in the range [@c 0, @c AH_JSON_LEVEL_MAX].
     */
    uintX_t level;

    /**
     * The length of the string referred to by @a base, or the number of child
     * nodes if @a type is @c AH_JSON_TYPE_OBJECT or @c AH_JSON_TYPE_ARRAY.
     *
     * When @a type is @c AH_JSON_TYPE_OBJECT, the value of this field indicates
     * the total number of keys and values in this object. When @a type is
     * @c AH_JSON_TYPE_ARRAY, it indicates the total number of elements in this
     * array.
     *
     * @note The concrete type used to represent the current level varies across
     *       supported platforms. That type is, however, guaranteed to be able
     *       to hold any integer in the range [@c 0, @c AH_JSON_LENGTH_MAX].
     */
    uintX_t length;

#endif
};

/**
 * Parses @a src into an array of ah_json_val instances stored in @a dst.
 *
 * This function operates either with or without dynamic memory reallocation. To
 * enable the former, make sure that the ah_json_buf::values field of @a dst is
 * set to @c NULL and that ah_json_buf::length is set to @c 0. The
 * ah_json_buf::capacity field determines the initially allocated capacity.
 *
 * To make this function operate without dynamic memory allocation, make the
 * ah_json_buf::values field of @a dst point to an array you allocated. Its
 * capacity must be indicated by ah_json_buf::capacity and ah_json_buf::length
 * should be set to @c 0.
 *
 * @param src Pointer to initialized input buffer.
 * @param dst Pointer to initialized output buffer.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - The operation was successful.
 *   <li>@ref AH_EEOF      - @a src ended unexpectedly.
 *   <li>@ref AH_EILSEQ    - @a src contains invalid JSON.
 *   <li>@ref AH_EINVAL    - @a src is invalid, @a dst is @c NULL or @c dst->length is larger than
 *                           @c dst->capacity.
 *   <li>@ref AH_EINVAL    - @c dst->values is @c NULL, which enables dynamic reallocation, and
 *                           @c dst->length is not @c 0.
 *   <li>@ref AH_EOVERFLOW - @a src exceeded @ref AH_JSON_LEVEL_MAX or @ref AH_JSON_LENGTH_MAX.
 *   <li>@ref AH_ENOBUFS   - @a dst is out of empty values and dynamic reallocation is disabled.
 *   <li>@ref AH_ENOMEM    - @a dst is out of empty values and dynamic reallocation failed.
 * </ul>
 *
 * @note When this function returns, @a dst will be in a valid state unless the
 *       returned error code is @ref AH_EINVAL, in which case @a dst remains
 *       unmodified.
 */
ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst);

/**
 * Compares strings @a a and @a b while taking JSON escape sequences into
 * account.
 *
 * If, for example, this function is provided the two strings
 * <code>"I'm a 猫"</code> and <code>"I'm a \u732B"</code>, it will correctly
 * report them as being equal, despite the Chinese sign for "cat" being given as
 * an escape sequence in the second string.
 *
 * @param a        Pointer to first string.
 * @param a_length Length of @a a, excluding any NULL-terminator.
 * @param b        Pointer to second string.
 * @param b_length Length of @a b, excluding any NULL-terminator.
 * @return An integer greater than, equal to, or less than 0, depending on
 *         whether @a a is greater than, equal to, or less than @a b. The
 *         comparison is done using unsigned characters, so that @c \\200 is
 *         greater than @c \\0.
 */
ah_extern int ah_json_str_compare(const char* a, size_t a_length, const char* b, size_t b_length);

/**
 * Substitutes any UTF-8 code point below 32 and <code>"</code> with its
 * corresponding JSON escape sequence and writes the result to @a dst.
 *
 * If the operation is successful, the value pointer at by @a dst_length is
 * updated to reflect the final length of the string actually written to @a dst.
 *
 * @param src        Pointer to input buffer.
 * @param src_length Length of @a src, excluding any NULL-terminator.
 * @param dst        Pointer to output buffer.
 * @param dst_length Pointer to length of @a dst, in bytes.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - The operation was successful.
 *   <li>@ref AH_EINVAL    - @a src is @c NULL and @a src_length is not @c 0.
 *   <li>@ref AH_EINVAL    - @a dst_length is @c NULL.
 *   <li>@ref AH_EINVAL    - @a dst is @c NULL and the value pointed at by @a dst_length is not @c 0.
 *   <li>@ref AH_EOVERFLOW - @a dst not large enough to hold the escaped string.
 * </ul>
 */
ah_extern ah_err_t ah_json_str_escape(const char* src, size_t src_length, char* dst, size_t* dst_length);

/**
 * Substitutes any JSON escape sequences in @a src with their UTF-8 equivalents
 * and writes the result to @a dst.
 *
 * If the operation is successful, the value pointer at by @a dst_length is
 * updated to reflect the final length of the string actually written to @a dst.
 *
 * @param src        Pointer to input buffer.
 * @param src_length Length of @a src, excluding any NULL-terminator.
 * @param dst        Pointer to output buffer.
 * @param dst_length Pointer to length of @a dst, in bytes.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE     - The operation was successful.
 *   <li>@ref AH_EILSEQ    - @a src contains an invalid JSON escape sequence.
 *   <li>@ref AH_EINVAL    - @a src is @c NULL and @a src_length is not @c 0.
 *   <li>@ref AH_EINVAL    - @a dst_length is @c NULL.
 *   <li>@ref AH_EINVAL    - @a dst is @c NULL and the value pointed at by @a dst_length is not @c 0.
 *   <li>@ref AH_EOVERFLOW - @a dst not large enough to hold the unescaped string.
 * </ul>
 */
ah_extern ah_err_t ah_json_str_unescape(const char* src, size_t src_length, char* dst, size_t* dst_length);

#endif
