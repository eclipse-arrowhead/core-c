// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

#include "defs.h"
#include "err.h"

#include <stddef.h>
#include <stdint.h>

#if AH_USE_IOVEC
struct iovec;
#endif

struct ah_buf {
    uint8_t* octets;
    size_t size;
};

struct ah_bufvec {
    struct ah_buf* items;
    size_t length;
};

#if AH_USE_IOVEC
ah_extern ah_err_t ah_bufvec_from_iovec(struct ah_bufvec* bufvec, struct iovec* iov, int iovcnt);
ah_extern ah_err_t ah_bufvec_into_iovec(struct ah_bufvec* bufvec, struct iovec** iov, int* iovcnt);
#endif

#endif
