// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_WIN32_BUF_H_
#define AH_INTERNAL_WIN32_BUF_H_

#include "../defs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define AH_I_BUF_PLATFORM_FIELDS                                                                                       \
    ULONG _size;                                                                                                       \
    uint8_t* _base;

typedef struct _WSABUF WSABUF;

ah_inline WSABUF* ah_i_buf_into_wsabuf(ah_buf_t* buf)
{
    return (WSABUF*) buf;
}

ah_extern void ah_i_bufs_from_wsabufs(ah_bufs_t* bufs, WSABUF* buffers, ULONG buffer_count);
ah_extern ah_err_t ah_i_bufs_into_wsabufs(ah_bufs_t* bufs, WSABUF** buffers, ULONG* buffer_count);

#endif
