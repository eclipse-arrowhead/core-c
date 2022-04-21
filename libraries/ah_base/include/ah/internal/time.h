// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TIME_H_
#define AH_INTERNAL_TIME_H_

#include "../defs.h"

#if AH_USE_URING
#    include "uring/time.h"
#elif AH_IS_DARWIN
#    include "darwin/time.h"
#elif AH_IS_WIN32
#    include "win32/time.h"
#endif

#define AH_I_TIME_FIELDS AH_I_TIME_PLATFORM_FIELDS

#endif
