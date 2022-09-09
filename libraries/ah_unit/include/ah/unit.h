// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UNIT_H_
#define AH_UNIT_H_

/**
 * @file
 * Unit testing utilities.
 *
 * This file provides data structures and functions for writing <em>automated
 * unit tests</em>. To use these utilities, you must first allocate an
 * ah_unit_res instance and zero its memory. You then pass it to the assertion
 * functions provided here, such as ah_unit_assert() or
 * ah_unit_assert_eq_uintmax(). When all relevant assertions have been executed,
 * you call ah_unit_print_results() with your result accumulator, which prints a
 * summary of your assertion results.
 *
 * You are free to use the functions and structures here however you wish, and
 * organize them in the manner best suited for the software you wish to test.
 *
 * @note On platforms where a distinction is made between regular printing and
 *       error printing (such as @c STDOUT and @c STDERR on POSIX systems),
 *       failure messages are printed to the latter.
 */

#include <ah/defs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Expands into a unit testing context.
 *
 * That context will contains information about the file and line at which the
 * macro appears. It makes it easier for you to know where failed assertions are
 * executed.
 *
 * @see ah_unit_ctx
 */
#define AH_UNIT_CTX \
 ((ah_unit_ctx_t) { .file = __FILE__, .line = __LINE__ })

typedef struct ah_unit_ctx ah_unit_ctx_t;
typedef struct ah_unit_res ah_unit_res_t;

/**
 * Unit testing context.
 *
 * Describes the location at which a certain assertion appears in a source code
 * file.
 *
 * @note Instances of this structure can appropriately be created by using the
 * @ref AH_UNIT_CTX macro.
 */
struct ah_unit_ctx {
    /** The path of the file in which the assertion is executed. */
    const char* file;

    /** The line number in @a file where the assertion is executed. */
    int line;
};

/**
 * Unit testing result accumulator.
 *
 * Initialize instances of this type by setting all of their fields to zero.
 */
struct ah_unit_res {
    /** The number of executed assertions. */
    int assertion_count;

    /** The numner of executed assertions that failed. */
    int fail_count;
};

/**
 * @name Assertions
 * @{
 */

/**
 * Asserts that @a is_success is @c true or prints failure message.
 *
 * @param ctx        Unit testing context.
 * @param res        Pointer to result accumulator, or @c NULL.
 * @param is_success Whether or not some arbitrary test was successful.
 * @param format     Format string, accepting the same patterns as C99 printf().
 * @param ...        @a format arguments.
 * @return The value of @a is_success.
 *
 * @warning An error message is printed and ah_abort() is called if @a format is
 *          @c NULL.
 */
ah_extern bool ah_unit_assert(ah_unit_ctx_t ctx, ah_unit_res_t* res, bool is_success, const char* format, ...);

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * The comparison is made using C99 strcmp().
 *
 * @param ctx      Unit testing context.
 * @param res      Pointer to result accumulator, or @c NULL.
 * @param actual   The string produced by your test.
 * @param expected The string you expect your test to produce.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 */
ah_extern bool ah_unit_assert_eq_cstr(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* actual, const char* expected);

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * If the comparison fails, @a to_str is used to present @a actual and
 * @a expected as strings in the printed failure message.
 *
 * @param ctx      Unit testing context.
 * @param res      Pointer to result accumulator, or @c NULL.
 * @param actual   The enumerator produced by your test.
 * @param expected The enumerator you expect your test to produce.
 * @param to_str   Pointer to function able to produce a constant string
 *                 representation of a given enumerator.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 *
 * @warning An error message is printed and ah_abort() is called if @a to_str is
 *          @c NULL.
 */
ah_extern bool ah_unit_assert_eq_enum(ah_unit_ctx_t ctx, ah_unit_res_t* res, int actual, int expected, const char* (*to_str)(int) );

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * If the comparison fails, ah_strerror_r() is used to present @a actual and
 * @a expected as strings in the printed failure message.
 *
 * @param ctx      Unit testing context.
 * @param res      Pointer to result accumulator, or @c NULL.
 * @param actual   The enumerator produced by your test.
 * @param expected The enumerator you expect your test to produce.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 */
ah_extern bool ah_unit_assert_eq_err(ah_unit_ctx_t ctx, ah_unit_res_t* res, ah_err_t actual, ah_err_t expected);

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * The comparison is made using C99 memcmp() after a check that @a actual_size
 * is equal to @a expected_size.
 *
 * @param ctx           Unit testing context.
 * @param res           Pointer to result accumulator, or @c NULL.
 * @param actual        The array of unsigned bytes produced by your test.
 * @param actual_size   Size of @a actual, in bytes.
 * @param expected      The array of unsigned bytes you expect your test to produce.
 * @param expected_size Size of @a expected, in bytes.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 */
ah_extern bool ah_unit_assert_eq_mem(ah_unit_ctx_t ctx, ah_unit_res_t* res, const void* actual, size_t actual_size, const void* expected, size_t expected_size);

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * @param ctx      Unit testing context.
 * @param res      Pointer to result accumulator, or @c NULL.
 * @param actual   The signed integer produced by your test.
 * @param expected The signed integer you expect your test to produce.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 */
ah_extern bool ah_unit_assert_eq_intmax(ah_unit_ctx_t ctx, ah_unit_res_t* res, intmax_t actual, intmax_t expected);

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * The comparison is made using C99 memcmp() after a check that @a actual_size
 * is equal to @a expected_size. The only difference between this function and
 * ah_unit_assert_eq_mem() is that this function assumes @a actual and
 * @a expected to contain printable characters.
 *
 * @param ctx             Unit testing context.
 * @param res             Pointer to result accumulator, or @c NUlL.
 * @param actual          The string produced by your test.
 * @param actual_length   Size of @a actual, in bytes.
 * @param expected        The string you expect your test to produce.
 * @param expected_length Size of @a expected, in bytes.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 */
ah_extern bool ah_unit_assert_eq_str(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* actual, size_t actual_length, const char* expected, size_t expected_length);

/**
 * Asserts that @a actual is equal to @a expected or prints failure message.
 *
 * @param ctx      Unit testing context.
 * @param res      Pointer to result accumulator, or @c NULL.
 * @param actual   The unsigned integer produced by your test.
 * @param expected The unsigned integer you expect your test to produce.
 * @return @c true only if @a actual is equal to @a expected. @c false
 *         otherwise.
 */
ah_extern bool ah_unit_assert_eq_uintmax(ah_unit_ctx_t ctx, ah_unit_res_t* res, uintmax_t actual, uintmax_t expected);

/**
 * Increments assertion count and failure count in @a res and prints failure
 * message.
 *
 * @param ctx    Unit testing context.
 * @param res    Pointer to result accumulator, or @c NULL.
 * @param format Format string, accepting the same patterns as C99 printf().
 * @param ...    @a format arguments.
 *
 * @warning An error message is printed and ah_abort() is called if @a format is
 *          @c NULL.
 */
ah_extern void ah_unit_fail(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* format, ...);

/**
 * Increments assertion count in @a res.
 *
 * @param res Pointer to result accumulator, or @c NULL.
 *
 * @note Does nothing if @a res is @c NULL.
 */
ah_extern void ah_unit_pass(ah_unit_res_t* res);

/** @} */

/**
 * @name Results
 * @{
 */

/**
 * Prints results accumulated in @a res.
 *
 * If @a res contains no failure, a regular message is printed. Otherwise a
 * failure message is printed.
 *
 * @param res Pointer to result accumulator, or @c NULL.
 *
 * @note Prints a message indicating that nothing could be reported if @a res is
 *       @c NULL.
 */
ah_extern void ah_unit_print_results(const ah_unit_res_t* res);

/** @} */

/**
 * @name Unit Library Version Details
 * @{
 */

/**
 * Gets human-readable representation of version of the Unit library.
 *
 * @return Constant string representation of version.
 */
ah_extern const char* ah_unit_lib_version_str(void);

/**
 * Gets major version of the Unit library.
 *
 * @return Major version indicator.
 */
ah_extern unsigned short ah_unit_lib_version_major(void);

/**
 * Gets minor version of the Unit library.
 *
 * @return Minor version indicator.
 */
ah_extern unsigned short ah_unit_lib_version_minor(void);

/**
 * Gets patch version of the Unit library.
 *
 * @return Patch version indicator.
 */
ah_extern unsigned short ah_unit_lib_version_patch(void);

/** @} */

#endif
