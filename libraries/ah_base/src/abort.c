#include <ah/abort.h>
#include <ah/defs.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>

#if AH_USE_POSIX
#    include <unistd.h>
#endif

ah_extern void ah_abort()
{
#if AH_USE_POSIX

    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGABRT);
    (void) sigprocmask(SIG_UNBLOCK, &act.sa_mask, NULL);

    (void) kill(getpid(), SIGABRT);

#endif

#if AH_VIA_GCC || AH_VIA_CLANG

    __builtin_trap();

#else
#    error "No trap builtin is available via the used compiler."
#endif
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
