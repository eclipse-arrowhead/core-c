// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"

#include "ah/defs.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>

#if AH_IS_WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#endif

#if AH_HAS_POSIX
#    include <unistd.h>
#else
#    include <signal.h>
#endif

ah_extern void ah_abort()
{
#if AH_HAS_POSIX

    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGABRT);
    (void) sigprocmask(SIG_UNBLOCK, &act.sa_mask, NULL);

    (void) kill(getpid(), SIGABRT);

#else

    raise(SIGABRT);

#endif

    ah_trap();
}

ah_extern ah_noreturn void ah_abortf(const char* format, ...)
{
    fputs("[ABORT] ", stderr);

    va_list args;
    va_start(args, format);
    (void) vfprintf(stderr, format, args);
    va_end(args);

    fputc('\n', stderr);

    ah_abort();
}
