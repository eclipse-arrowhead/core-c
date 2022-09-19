// SPDX-License-Identifier: EPL-2.0

#ifndef AH_TIME_H_
#define AH_TIME_H_

/**
 * @file
 * Monotonic time querying and comparison.
 *
 * Here, functionality is provided for dealing with a monotonically increasing
 * platform clock. Such a clock can only be meaningfully compared to itself in
 * order to measure elapsed time. It cannot be used to determine what the
 * current global time is (such as what GMT date and time is current).
 */

#include "internal/_time.h"

#include <stdbool.h>
#include <stdint.h>

/**
 * Adds the appropriate ah_timediff_t postfix expression to number literal @a V.
 */
#define AH_TIMEDIFF_C(V) INT64_C(V)

#define AH_TIMEDIFF_NS AH_TIMEDIFF_C(1)              ///< Nanosecond ah_timediff multiplier.
#define AH_TIMEDIFF_US AH_TIMEDIFF_C(1000)           ///< Microsecond ah_timediff multiplier.
#define AH_TIMEDIFF_MS AH_TIMEDIFF_C(1000000)        ///< Millisecond ah_timediff multiplier.
#define AH_TIMEDIFF_S  AH_TIMEDIFF_C(1000000000)     ///< Second ah_timediff multiplier.
#define AH_TIMEDIFF_M  AH_TIMEDIFF_C(60000000000)    ///< Minute ah_timediff multiplier.
#define AH_TIMEDIFF_H  AH_TIMEDIFF_C(3600000000000)  ///< Hour ah_timediff multiplier.
#define AH_TIMEDIFF_D  AH_TIMEDIFF_C(86400000000000) ///< 24-hour day ah_timediff multiplier.

/** Smallest representable ah_timediff value. */
#define AH_TIMEDIFF_MIN INT64_MIN

/** Largest representable ah_timediff value. */
#define AH_TIMEDIFF_MAX INT64_MAX

/**
 * Reference to a point in time, measured from an arbitrary point in the past.
 *
 * @note All fields of this data structure are @e private in the sense that a
 *       user of this API should not access them directly.
 */
struct ah_time {
    AH_I_TIME_FIELDS
};

/**
 * The difference between two ah_time instances, measured in nanoseconds.
 *
 * This type is guaranteed to be a signed 64-bit integer on all supported
 * platforms.
 */
typedef int64_t ah_timediff_t;

/**
 * Gets the current monotonic time, as reported by the platform.
 *
 * What concrete platform provision is consulted varies with the targeted
 * platform. The following table outlines what time sources are used on the
 * supported platforms:
 *
 * <table>
 *   <caption id="time-sources">Time sources</caption>
 *   <tr>
 *     <th>Platform
 *     <th>Source
 *   <tr>
 *     <td>Darwin
 *     <td><a href="https://developer.apple.com/documentation/kernel/1462446-mach_absolute_time">mach_absolute_time()</a>
 *   <tr>
 *     <td>Linux
 *     <td><a href="https://linux.die.net/man/3/clock_gettime">clock_gettime(CLOCK_MONOTONIC)</a>
 *   <tr>
 *     <td>Win32
 *     <td><a href="https://docs.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter">QueryPerformanceCounter()</a>
 * </table>
 *
 * @return Current time.
 */
ah_extern ah_time_t ah_time_now(void);

/**
 * Calculates the difference between the times @a a and @a b.
 *
 * @param a First time.
 * @param b Second time.
 * @param diff Pointer to receiver of difference between @a a and @a b.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a diff is NULL.
 *   <li>@ref AH_ERANGE - Subtracting @a b from @a a produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_time_diff(ah_time_t a, ah_time_t b, ah_timediff_t* diff);

/**
 * Checks if @a a and @a b represent the same time.
 *
 * @param a First time.
 * @param b Second time.
 * @return @c true only if @a a is identical to @a b. @c false otherwise.
 */
ah_extern bool ah_time_eq(ah_time_t a, ah_time_t b);

/**
 * Compares @a a to @a b.
 *
 * @param a First time.
 * @param b Second time.
 * @return An an integer greater than, equal to, or less than 0, depending on
 *         if @a a is greater than, equal to, or less than @a b.
 */
ah_extern int ah_time_cmp(ah_time_t a, ah_time_t b);

/**
 * Increases @a time by @a diff, storing the result to @a result.
 *
 * @param time Increased time.
 * @param diff Increment.
 * @param result Pointer to result receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Adding @a diff to @a time produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_time_add(ah_time_t time, ah_timediff_t diff, ah_time_t* result);

/**
 * Decreases @a time by @a diff, storing the result to @a result.
 *
 * @param time Decreased time.
 * @param diff Decrement.
 * @param result Pointer to result receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Subtracting @a diff from @a time produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_time_sub(ah_time_t time, ah_timediff_t diff, ah_time_t* result);

/**
 * Checks if @a a represents a point in time located after @a b.
 *
 * @param a First time.
 * @param b Second time.
 * @return @c true only if @a a occurs after @a b. @c false otherwise.
 */
ah_extern bool ah_time_is_after(ah_time_t a, ah_time_t b);

/**
 * Checks if @a a represents a point in time located before @a b.
 *
 * @param a First time.
 * @param b Second time.
 * @return @c true only if @a a occurs before @a b. @c false otherwise.
 */
ah_extern bool ah_time_is_before(ah_time_t a, ah_time_t b);

/**
 * Checks if @a time is the zero time.
 *
 * @param time Time.
 * @return @c true only if @a time is zeroed.
 *
 * @note The zero time can be produced by setting the memory of an ah_time
 * instance to all zeroes.
 */
ah_extern bool ah_time_is_zero(ah_time_t time);

/**
 * Adds @a a to @a b, storing the result to @a result.
 *
 * @param a First time difference.
 * @param b Second time difference.
 * @param result Pointer to result receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Adding @a a and @a b produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_timediff_add(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);

/**
 * Divides @a a with @a b, storing the result to @a result.
 *
 * @param a First time difference.
 * @param b Second time difference.
 * @param result Pointer to result receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EDOM   - @a b is @c 0.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Dividing @a a with @a b produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_timediff_div(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);

/**
 * Multiplies @a a with @a b, storing the result to @a result.
 *
 * @param a First time difference.
 * @param b Second time difference.
 * @param result Pointer to result receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Multiplying @a a with @a b produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_timediff_mul(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);

/**
 * Subtracts @a a and @a b, storing the result to @a result.
 *
 * @param a First time difference.
 * @param b Second time difference.
 * @param result Pointer to result receiver.
 * @return One of the following error codes: <ul>
 *   <li>@ref AH_ENONE  - Operation successful.
 *   <li>@ref AH_EINVAL - @a result is @c NULL.
 *   <li>@ref AH_ERANGE - Subtracting @a a and @a b produced an unrepresentable result.
 * </ul>
 */
ah_extern ah_err_t ah_timediff_sub(ah_timediff_t a, ah_timediff_t b, ah_timediff_t* result);

#endif
