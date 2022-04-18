// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

#include "defs.h"

#include <stddef.h>
#include <stdint.h>

#if AH_IS_WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#endif

#if AH_IS_WIN32
typedef struct _WSABUF WSABUF;
#elif AH_HAS_POSIX
struct iovec;
#endif

struct ah_buf {
#if AH_IS_WIN32
    ULONG size;
    uint8_t* octets;
#else
    uint8_t* octets;
    size_t size;
#endif
};

struct ah_bufvec {
    ah_buf_t* items;
    size_t length;
};

ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, void* data, const size_t size);

#if AH_IS_WIN32
ah_extern ah_err_t ah_bufvec_from_wsabufs(ah_bufvec_t* bufvec, WSABUF* buffers, ULONG buffer_count);
ah_extern ah_err_t ah_bufvec_into_wsabufs(ah_bufvec_t* bufvec, WSABUF** buffers, ULONG* buffer_count);
#elif AH_HAS_POSIX
ah_extern ah_err_t ah_bufvec_from_iovec(ah_bufvec_t* bufvec, struct iovec* iov, int iovcnt);
ah_extern ah_err_t ah_bufvec_into_iovec(ah_bufvec_t* bufvec, struct iovec** iov, int* iovcnt);
#endif

#endif
