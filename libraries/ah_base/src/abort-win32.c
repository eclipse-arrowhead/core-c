// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/abort.h"
#include "ah/defs.h"

#include <signal.h>

ah_extern void ah_abort()
{
    raise(SIGABRT);
    ah_trap();
}
