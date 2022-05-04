// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/err.h"

ah_extern ah_err_t ah_buf_shrinkl(ah_buf_t* buf, size_t size)
{
    ah_assert_if_debug(buf != NULL);

    if (size > ah_buf_get_size(buf)) {
        return AH_EOVERFLOW;
    }

    return ah_buf_init(buf, &ah_buf_get_base(buf)[size], ah_buf_get_size(buf) - size);
}
