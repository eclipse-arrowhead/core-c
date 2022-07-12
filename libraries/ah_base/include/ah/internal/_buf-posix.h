// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_POSIX_BUF_H_
#define AH_INTERNAL_POSIX_BUF_H_

#include "../defs.h"

#include <stddef.h>
#include <stdint.h>

#define AH_I_BUF_PLATFORM_SIZE_MAX SIZE_MAX

struct iovec;

static inline struct iovec* ah_i_buf_into_iovec(ah_buf_t* buf)
{
    return (struct iovec*) buf;
}

static inline ah_buf_t* ah_i_buf_from_iovec(struct iovec* iovec)
{
    return (ah_buf_t*) iovec;
}

#endif
