// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"
#include "ah/intrin.h"

#include <signal.h>
#include <unistd.h>

ah_extern void ah_abort()
{
    struct sigaction act;
    (void) sigemptyset(&act.sa_mask);
    (void) sigaddset(&act.sa_mask, SIGABRT);
    (void) sigprocmask(SIG_UNBLOCK, &act.sa_mask, NULL);

    (void) kill(getpid(), SIGABRT);

    ah_trap();
}
