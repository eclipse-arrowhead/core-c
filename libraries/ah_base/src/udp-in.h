// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_UDP_IN_H_
#define SRC_UDP_IN_H_

#include "ah/udp.h"

ah_err_t ah_i_udp_in_alloc_for(ah_udp_in_t** owner_ptr);
ah_err_t ah_i_udp_in_detach(ah_udp_in_t* in);
void ah_i_udp_in_free(ah_udp_in_t* in);
void ah_i_udp_in_reset(ah_udp_in_t* in);

#endif
