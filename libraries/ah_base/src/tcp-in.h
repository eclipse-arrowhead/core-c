// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TCP_IN_H_
#define SRC_TCP_IN_H_

#include "ah/tcp.h"

ah_err_t ah_i_tcp_in_alloc_for(ah_tcp_in_t** owner_ptr);
ah_err_t ah_i_tcp_in_detach(ah_tcp_in_t* in);
void ah_i_tcp_in_free(ah_tcp_in_t* in);
ah_err_t ah_i_tcp_in_repackage(ah_tcp_in_t* in);
void ah_i_tcp_in_reset(ah_tcp_in_t* in);

#endif
