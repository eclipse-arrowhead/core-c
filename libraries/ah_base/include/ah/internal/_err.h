// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_ERR_H_
#define AH_INTERNAL_ERR_H_

#include "../defs.h"

#include <stddef.h>

#if AH_IS_WIN32
# include <winerror.h>
#else
# include <errno.h>
#endif

#if AH_IS_WIN32
# define AH_I_ERR_ONE_OF(POSIX_CODE, WIN32_CODE) WIN32_CODE
#else
# define AH_I_ERR_ONE_OF(POSIX_CODE, WIN32_CODE) POSIX_CODE
#endif

#endif
