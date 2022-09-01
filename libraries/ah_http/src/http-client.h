// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_HTTP_CLIENT_H_
#define SRC_HTTP_CLIENT_H_

#include "ah/http.h"

// Incoming message states.
#define AH_I_HTTP_CLIENT_IN_STATE_INIT       0x01
#define AH_I_HTTP_CLIENT_IN_STATE_LINE       0x02
#define AH_I_HTTP_CLIENT_IN_STATE_HEADERS    0x04
#define AH_I_HTTP_CLIENT_IN_STATE_DATA       0x08
#define AH_I_HTTP_CLIENT_IN_STATE_CHUNK_LINE 0x10
#define AH_I_HTTP_CLIENT_IN_STATE_CHUNK_DATA 0x20
#define AH_I_HTTP_CLIENT_IN_STATE_TRAILER    0x40

extern const ah_tcp_conn_cbs_t ah_i_http_conn_cbs;

#endif
