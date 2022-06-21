// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_UDP_IN_H_
#define SRC_UDP_IN_H_

#include "ah/udp.h"

ah_udp_in_t* ah_i_udp_in_alloc();
void ah_i_udp_in_refresh(ah_udp_in_t** in, ah_udp_sock_in_mode_t mode);
void ah_i_udp_in_free(ah_udp_in_t* in);

#endif
