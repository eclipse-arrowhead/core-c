// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_WIN32_BUF_H_
#define AH_INTERNAL_WIN32_BUF_H_

#include "../defs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define AH_I_BUF_PLATFORM_SIZE_MAX ULONG_MAX

typedef struct _WSABUF WSABUF;

static inline WSABUF* ah_i_buf_into_wsabuf(ah_buf_t* buf)
{
    return (WSABUF*) buf;
}

#endif
