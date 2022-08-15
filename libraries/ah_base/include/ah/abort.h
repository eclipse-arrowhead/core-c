// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ABORT_H_
#define AH_ABORT_H_

/// \brief Process abortion routines.
/// \file
///
/// Various functions for abnormally terminating the application process,
/// typically to indicate that some irrecoverable behavior has been observed.
///
/// \note In contrast to the abort() function of the C99 standard library, the
/// functions here must have well-defined behavior on each platform they are
/// implemented for.

#include "defs.h"

/// \brief Aborts application process without a message.
///
/// The function triggers the following behaviors depending on the current
/// platform:
///
/// \li <b>[POSIX]</b> The \c SIGABRT signal is unblocked and then raised.
/// \li <b>[Win32]</b> The \c SIGABRT signal is raised.
ah_extern ah_noreturn void ah_abort(void);

/// \brief Prints a formatted message and then calls ah_abort().
///
/// On platforms where an standard error file is available, the formatted
/// message is written to that file.
///
/// \param format A format string, specified using the same patterns as those
///               supported by the C99 printf() function.
/// \param ...    Format arguments.
ah_extern ah_noreturn void ah_abortf(const char* format, ...);

#endif
