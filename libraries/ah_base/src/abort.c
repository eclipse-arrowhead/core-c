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
#    include <Windows.h>
#endif

#if AH_USE_POSIX
#    include <unistd.h>
#else
#    include <signal.h>
#endif

ah_extern void ah_abort()
{
#if AH_USE_POSIX

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

#if AH_IS_WIN32
ah_extern ah_noreturn void ah_abort_with_last_win32_error(const char* message)
{
    DWORD err = GetLastError();
    char buf[256];

    WORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    size_t size = FormatMessageA(flags, NULL, err, 0, (LPSTR) &buf, sizeof(buf), NULL);

    ah_abortf("%s; %*.s", message, size, buf);
}
#endif
