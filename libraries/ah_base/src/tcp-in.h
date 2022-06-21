// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_TCP_IN_H_
#define SRC_TCP_IN_H_

#include "ah/tcp.h"

ah_tcp_in_t* ah_i_tcp_in_alloc(void);
void ah_i_tcp_in_refresh(ah_tcp_in_t** in, ah_tcp_conn_in_mode_t mode);
void ah_i_tcp_in_free(ah_tcp_in_t* in);

#endif
