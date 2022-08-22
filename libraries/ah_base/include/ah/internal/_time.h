// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TIME_H_
#define AH_INTERNAL_TIME_H_

#include "../defs.h"

#if AH_USE_URING
# include "_time-uring.h"
#elif AH_IS_DARWIN
# include "_time-darwin.h"
#elif AH_IS_WIN32
# include "_time-win32.h"
#endif

#define AH_I_TIME_FIELDS AH_I_TIME_PLATFORM_FIELDS

#endif
