// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ABORT_H_
#define AH_ABORT_H_

/**
 * @file
 * Process abortion routines.
 *
 * Various functions for abnormally terminating the application process,
 * typically to indicate that some irrecoverable behavior has been observed.
 *
 * @note In contrast to the abort() function of the C99 standard library, the
 * functions here must be able to guarantee what the results of calling them
 * are.
 */

#include "defs.h"

/**
 * Aborts application process without a message.
 *
 * Invoking this function results in the following reactions on each supported
 * platform:
 *
 * @li [Darwin, Linux] The @c SIGABRT signal is unblocked and then raised.
 * @li [Win32] The @c SIGABRT signal is raised.
 */
ah_extern ah_noreturn void ah_abort(void);

/**
 * Prints a formatted message and then calls ah_abort().
 *
 * On platforms where an standard error file is available, the formatted
 * message is written to that file.
 *
 * @param format A format string, specified using the same patterns as those
 *               supported by the C99 printf() function.
 * @param ...    Format arguments.
 */
ah_extern ah_noreturn void ah_abortf(const char* format, ...);

#endif
