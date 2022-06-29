// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "mbedtls-utils.h"

#include "mbedtls-client.h"
#include "mbedtls-server.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>

const ah_tcp_vtab_t ah_i_mbedtls_tcp_vtab = {
    .conn_open = ah_i_mbedtls_client_open,
    .conn_connect = ah_i_mbedtls_client_connect,
    .conn_read_start = ah_i_mbedtls_client_read_start,
    .conn_read_stop = ah_i_mbedtls_client_read_stop,
    .conn_write = ah_i_mbedtls_client_write,
    .conn_shutdown = ah_i_mbedtls_client_shutdown,
    .conn_close = ah_i_mbedtls_client_close,

    .listener_open = ah_i_tls_server_open,
    .listener_listen = ah_i_tls_server_listen,
    .listener_close = ah_i_tls_server_close,
};

ah_err_t ah_i_mbedtls_res_to_err(struct ah_i_mbedtls_errs* errs, int res)
{
    ah_assert_if_debug(errs != NULL);
    ah_assert_if_debug(res <= 0);

    switch (res) {
    case 0:
        return AH_ENONE;

    case MBEDTLS_ERR_ASN1_ALLOC_FAILED:
    case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
    case MBEDTLS_ERR_DHM_ALLOC_FAILED:
    case MBEDTLS_ERR_ECP_ALLOC_FAILED:
    case MBEDTLS_ERR_MD_ALLOC_FAILED:
    case MBEDTLS_ERR_MPI_ALLOC_FAILED:
    case MBEDTLS_ERR_PK_ALLOC_FAILED:
    case MBEDTLS_ERR_SSL_ALLOC_FAILED:
    case MBEDTLS_ERR_X509_ALLOC_FAILED:
        return AH_ENOMEM;

    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        return AH_ENOLINK;

    case MBEDTLS_ERR_SSL_CONN_EOF:
        return AH_EEOF;

    case MBEDTLS_ERR_ERROR_GENERIC_ERROR:
        if (errs->_pending_ah_err != AH_ENONE) {
            ah_err_t err = errs->_pending_ah_err;
            errs->_pending_ah_err = AH_ENONE;
            return err;
        }
        // fallthrough
    default:
        errs->_last_mbedtls_err = res;
        return AH_EDEP;
    }
}
