// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_BUF_H_
#define AH_INTERNAL_BUF_H_

#include "../defs.h"

#if AH_HAS_POSIX
# include "_buf-posix.h"
#elif AH_IS_WIN32
# include "_buf-win32.h"
#endif

#define AH_I_BUF_SIZE_MAX AH_I_BUF_PLATFORM_SIZE_MAX

#endif
