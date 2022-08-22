// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"

#include "ah/intrin.h"

#include <signal.h>

ah_extern void ah_abort(void)
{
    raise(SIGABRT);
    ah_trap();
}
