// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"

#include "ah/intrin.h"

#include <signal.h>
#include <unistd.h>

ah_extern void ah_abort(void)
{
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGABRT);
    (void) sigprocmask(SIG_UNBLOCK, &act.sa_mask, NULL);

    (void) kill(getpid(), SIGABRT);

    ah_trap();
}
