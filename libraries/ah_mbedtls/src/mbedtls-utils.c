// SPDX-License-Identifier: EPL-2.0

#include "mbedtls-utils.h"

#include "mbedtls-client.h"
#include "mbedtls-server.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>

const ah_tcp_trans_vtab_t ah_i_mbedtls_tcp_vtab = {
    .conn_init = ah_i_mbedtls_conn_init,
    .conn_open = ah_i_mbedtls_conn_open,
    .conn_connect = ah_i_mbedtls_conn_connect,
    .conn_read_start = ah_i_mbedtls_conn_read_start,
    .conn_read_stop = ah_i_mbedtls_conn_read_stop,
    .conn_write = ah_i_mbedtls_conn_write,
    .conn_shutdown = ah_i_mbedtls_conn_shutdown,
    .conn_close = ah_i_mbedtls_conn_close,
    .conn_get_family = ah_i_mbedtls_conn_get_family,
    .conn_get_laddr = ah_i_mbedtls_conn_get_laddr,
    .conn_get_raddr = ah_i_mbedtls_conn_get_raddr,
    .conn_get_loop = ah_i_mbedtls_conn_get_loop,
    .conn_get_obs_ctx = ah_i_mbedtls_conn_get_obs_ctx,
    .conn_is_closed = ah_i_mbedtls_conn_is_closed,
    .conn_is_readable = ah_i_mbedtls_conn_is_readable,
    .conn_is_reading = ah_i_mbedtls_conn_is_reading,
    .conn_is_writable = ah_i_mbedtls_conn_is_writable,
    .conn_set_keepalive = ah_i_mbedtls_conn_set_keepalive,
    .conn_set_nodelay = ah_i_mbedtls_conn_set_nodelay,
    .conn_set_reuseaddr = ah_i_mbedtls_conn_set_reuseaddr,

    .listener_init = ah_i_mbedtls_listener_init,
    .listener_open = ah_i_mbedtls_listener_open,
    .listener_listen = ah_i_mbedtls_listener_listen,
    .listener_close = ah_i_mbedtls_listener_close,
    .listener_get_family = ah_i_mbedtls_listener_get_family,
    .listener_get_laddr = ah_i_mbedtls_listener_get_laddr,
    .listener_get_loop = ah_i_mbedtls_listener_get_loop,
    .listener_get_obs_ctx = ah_i_mbedtls_listener_get_obs_ctx,
    .listener_is_closed = ah_i_mbedtls_listener_is_closed,
    .listener_set_keepalive = ah_i_mbedtls_listener_set_keepalive,
    .listener_set_nodelay = ah_i_mbedtls_listener_set_nodelay,
    .listener_set_reuseaddr = ah_i_mbedtls_listener_set_reuseaddr,

    .trans_prepare = ah_s_tcp_trans_prepare,
    .trans_retract = ah_i_tcp_trans_retract,
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
