// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"

#include "ah/defs.h"

#include <stdarg.h>
#include <stdio.h>

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
