// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_POSIX_BUF_H_
#define AH_INTERNAL_POSIX_BUF_H_

#include "../defs.h"

#include <stddef.h>

#define AH_I_BUF_PLATFORM_FIELDS \
 uint8_t* _base;                 \
 size_t _size;

struct iovec;

static inline struct iovec* ah_i_buf_into_iovec(ah_buf_t* buf)
{
    return (struct iovec*) buf;
}

static inline ah_buf_t* ah_i_buf_from_iovec(struct iovec* iovec)
{
    return (ah_buf_t*) iovec;
}

ah_extern void ah_i_bufs_from_iovec(ah_bufs_t* bufs, struct iovec* iov, size_t iovcnt);
ah_extern ah_err_t ah_i_bufs_into_iovecs(ah_bufs_t* bufs, struct iovec** iov, int* iovcnt);

#endif
