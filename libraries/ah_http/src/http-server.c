// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>

ah_extern ah_err_t ah_http_server_open(ah_http_server_t* srv, const ah_sockaddr_t* local_addr)
{
    (void) srv;
    (void) local_addr;
    return AH_EOPNOTSUPP;
}

ah_extern ah_err_t ah_http_server_send(ah_http_server_t* srv, const ah_http_ores_t* res)
{
    (void) srv;
    (void) res;
    return AH_EOPNOTSUPP;
}

ah_extern ah_err_t ah_http_server_close(ah_http_server_t* srv)
{
    (void) srv;
    return AH_EOPNOTSUPP;
}
