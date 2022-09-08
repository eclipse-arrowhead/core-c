// SPDX-License-Identifier: EPL-2.0

#include "mbedtls-client.h"

#include "mbedtls-server.h"
#include "mbedtls-utils.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <string.h>

#define AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_NORMAL      0u
#define AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR 1u
#define AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_CLOSE       2u

#define AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_PENDING 0u
#define AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_SENDING 1u
#define AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_SENT    2u

struct s_send_queue_entry {
    uint8_t _kind;
    uint8_t _state;
    struct ah_tcp_out _out;
};

static void s_conn_on_open(void* cln_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_connect(void* cln_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_read(void* cln_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_conn_on_write(void* cln_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_conn_on_close(void* cln_, ah_tcp_conn_t* conn, ah_err_t err);

static ah_err_t s_client_close_notify(ah_mbedtls_client_t* cln, uint8_t kind);
void s_client_handshake(ah_mbedtls_client_t* cln);
int s_client_read_ciphertext(void* cln_, unsigned char* buf, size_t len);
int s_client_write_ciphertext(void* cln_, const unsigned char* buf, size_t len);

const ah_tcp_conn_cbs_t ah_i_mbedtls_tcp_conn_cbs = {
    .on_open = s_conn_on_open,
    .on_connect = s_conn_on_connect,
    .on_read = s_conn_on_read,
    .on_write = s_conn_on_write,
    .on_close = s_conn_on_close,
};

ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* cln, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (cln == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = ah_i_mbedtls_client_prepare(cln, ssl_conf, on_handshake_done_cb);
    if (err == AH_ENONE) {
        cln->_trans = trans;
    }
    return err;
}

ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* cln)
{
    if (cln == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return cln->_errs._last_mbedtls_err;
}

ah_extern mbedtls_ssl_context* ah_mbedtls_client_get_ssl_context(ah_mbedtls_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return &cln->_ssl;
}

ah_extern ah_tcp_trans_t ah_mbedtls_client_as_tcp_trans(ah_mbedtls_client_t* cln)
{
    return (ah_tcp_trans_t) {
        .vtab = cln != NULL
            ? &ah_i_mbedtls_tcp_vtab
            : NULL,
        .ctx = cln,
    };
}

ah_extern ah_tcp_conn_t* ah_mbedtls_client_get_tcp_conn(ah_mbedtls_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return cln->_conn;
}

ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* cln)
{
    if (cln == NULL) {
        return;
    }

    mbedtls_ssl_free(&cln->_ssl);
    ah_i_ring_term(&cln->_out_queue_ciphertext);

    if (cln->_server != NULL) {
        ah_i_tls_server_free_accepted_client(cln->_server, cln);
    }
}

ah_err_t ah_i_mbedtls_client_prepare(ah_mbedtls_client_t* cln, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (cln == NULL || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    *cln = (ah_mbedtls_client_t) {
        ._on_handshake_done_cb = on_handshake_done_cb,
    };

    ah_err_t err = ah_i_ring_init(&cln->_out_queue_ciphertext, 4u, sizeof(struct s_send_queue_entry));
    if (err != AH_ENONE) {
        return err;
    }

    mbedtls_ssl_init(&cln->_ssl);
    int res = mbedtls_ssl_setup(&cln->_ssl, ssl_conf);
    if (res != 0) {
        ah_i_ring_term(&cln->_out_queue_ciphertext);
        return ah_i_mbedtls_res_to_err(&cln->_errs, res);
    }

    mbedtls_ssl_set_bio(&cln->_ssl, cln, s_client_write_ciphertext, s_client_read_ciphertext, NULL);

    return AH_ENONE;
}

// Called to get handshake data or encrypted payload data, if available.
int s_client_read_ciphertext(void* cln_, unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    if (buf == NULL && len != 0u) {
        err = AH_EINTERN;
        goto handle_err;
    }

    if (cln->_in_ciphertext == NULL) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    size_t n_available_bytes = ah_rw_get_readable_size(&cln->_in_ciphertext->rw);
    if (n_available_bytes == 0u) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (len > n_available_bytes) {
        len = n_available_bytes;
    }
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    if (!ah_rw_readn(&cln->_in_ciphertext->rw, buf, len)) {
        err = AH_EINTERN;
        goto handle_err;
    }

    return (int) len;

handle_err:
    cln->_errs._pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

// Called to send handshake data or encrypted payload data.
int s_client_write_ciphertext(void* cln_, const unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    ah_tcp_conn_t* conn = cln->_conn;
    if (conn == NULL) {
        err = AH_EINTERN;
        goto handle_err;
    }

    if (buf == NULL && len != 0u) {
        err = AH_EINTERN;
        goto handle_err;
    }

    if (len > INT_MAX) {
        err = AH_EINTERN;
        goto handle_err;
    }

    struct s_send_queue_entry* entry = ah_i_ring_peek(&cln->_out_queue_ciphertext);
    if (entry == NULL) {
        if (cln->_is_handshake_done) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        entry = ah_i_ring_alloc(&cln->_out_queue_ciphertext);
        if (entry == NULL) {
            err = AH_ENOMEM;
            goto handle_err;
        }
        goto state_pending;
    }

    switch (entry->_state) {
    state_pending:
    case AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_PENDING: {
        err = ah_buf_init(&entry->_out.buf, (void*) buf, (size_t) len);
        if (err != AH_ENONE) {
            goto handle_err;
        }
        entry->_state = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_SENDING;
        break;
    }

    case AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_SENDING: {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    case AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_SENT: {
        ah_i_ring_skip(&cln->_out_queue_ciphertext);
        size_t size = entry->_out.buf.size;
        if (size != (size_t) len) {
            err = AH_EINTERN;
            goto handle_err;
        }
        return (int) size;
    }

    default:
        err = AH_EINTERN;
        goto handle_err;
    }

    if (cln->_trans.vtab == NULL || cln->_trans.vtab->conn_write == NULL) {
        err = AH_EINTERN;
        goto handle_err;
    }
    err = cln->_trans.vtab->conn_write(cln->_trans.ctx, conn, &entry->_out);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return MBEDTLS_ERR_SSL_WANT_WRITE;

handle_err:
    ah_i_ring_skip(&cln->_out_queue_ciphertext);
    cln->_errs._pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

void ah_i_mbedtls_client_retract(ah_mbedtls_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    ah_i_ring_term(&cln->_out_queue_ciphertext);
    mbedtls_ssl_free(&cln->_ssl);
}

ah_err_t ah_i_mbedtls_conn_init(void* cln_, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs)
{
    ah_mbedtls_client_t* cln = cln_;

    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_init == NULL
        || conn == NULL || !ah_tcp_conn_cbs_is_valid_for_connection(obs.cbs)) {
        return AH_EINVAL;
    }

    if (cln->_conn != NULL) {
        return AH_ESTATE;
    }

    cln->_conn = conn;
    cln->_conn_obs = obs;

    return cln->_trans.vtab->conn_init(cln->_trans.ctx, conn, loop, trans, (ah_tcp_conn_obs_t) { &ah_i_mbedtls_tcp_conn_cbs, cln });
}

ah_err_t ah_i_mbedtls_conn_open(void* cln_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_open == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_open(cln->_trans.ctx, conn, laddr);
}

static void s_conn_on_open(void* cln_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* cln = cln_;
    ah_assert_if_debug(cln != NULL && cln->_conn_obs.cbs != NULL && cln->_conn_obs.cbs->on_open != NULL);
    cln->_conn_obs.cbs->on_open(cln->_conn_obs.ctx, conn, err);
}

ah_err_t ah_i_mbedtls_conn_connect(void* cln_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_connect == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_connect(cln->_trans.ctx, conn, raddr);
}

static void s_conn_on_connect(void* cln_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* cln = cln_;
    ah_assert_if_debug(cln != NULL && cln->_conn_obs.cbs != NULL && cln->_conn_obs.cbs->on_connect != NULL);

    cln->_is_handshake_done = false;

    cln->_conn_obs.cbs->on_connect(cln->_conn_obs.ctx, conn, err);
}

ah_err_t ah_i_mbedtls_conn_read_start(void* cln_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_read_start == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    err = ah_tcp_in_alloc_for(&cln->_in_plaintext);
    if (err != AH_ENONE) {
        return err;
    }

    err = cln->_trans.vtab->conn_read_start(cln->_trans.ctx, conn);
    if (err != AH_ENONE) {
        ah_tcp_in_free(cln->_in_plaintext);
        return err;
    }

    s_client_handshake(cln);

    return AH_ENONE;
}

void s_client_handshake(ah_mbedtls_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    int res;
    ah_err_t err;

    res = mbedtls_ssl_handshake(&cln->_ssl);

    switch (res) {
    case 0:
        cln->_is_handshake_done = true;

        const mbedtls_x509_crt* peer_cert;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        peer_cert = mbedtls_ssl_get_peer_cert(&cln->_ssl);
#else
        peer_cert = NULL;
#endif
        cln->_on_handshake_done_cb(cln, peer_cert, AH_ENONE);

        return;

    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        return;

    case MBEDTLS_ERR_ERROR_GENERIC_ERROR:
        if (cln->_errs._pending_ah_err != AH_ENONE) {
            err = cln->_errs._pending_ah_err;
            cln->_errs._pending_ah_err = AH_ENONE;
            break;
        }
        // fallthrough

    default:
        cln->_errs._last_mbedtls_err = res;
        err = AH_EDEP;
        break;
    }

    cln->_on_handshake_done_cb(cln, NULL, err);
}

static void s_conn_on_read(void* cln_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    ah_mbedtls_client_t* cln = cln_;
    ah_assert_if_debug(cln != NULL && cln->_conn_obs.cbs != NULL && cln->_conn_obs.cbs->on_read != NULL);

    if (err != AH_ENONE) {
        goto handle_err;
    }

    cln->_in_ciphertext = in;

handshake_again:
    if (!cln->_is_handshake_done) {
        s_client_handshake(cln);

        if (!cln->_is_handshake_done) {
            return;
        }
    }

    while (ah_rw_is_readable(&cln->_in_ciphertext->rw)) {
        void* buf = cln->_in_plaintext->rw.w;
        size_t len = ah_rw_get_writable_size(&cln->_in_plaintext->rw);

        // This call will make MbedTLS pull the ciphertext in
        // `cln->_in_ciphertext` through the appropriate decryption
        // algorithms and write the result to `cln->_in_plaintext`. See also
        // `ah_i_mbedtls_client_read_ciphertext()`.
        int res = mbedtls_ssl_read(&cln->_ssl, buf, len);

        if (res <= 0) {
            switch (res) {
            case 0:
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                ah_assert_if_debug(cln != NULL && cln->_trans.vtab != NULL && cln->_trans.vtab->conn_shutdown != NULL);
                err = cln->_trans.vtab->conn_shutdown(cln->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
                if (err == AH_ESTATE || err == AH_ENOTCONN) {
                    return;
                }
                if (err == AH_ENONE) {
                    err = AH_EEOF;
                }
                goto handle_err;

            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                cln->_is_handshake_done = false;
                goto handshake_again;

            default:
                cln->_errs._last_mbedtls_err = res;
                err = AH_EDEP;
                goto handle_err;
            }
        }

        if (!ah_rw_juken(&cln->_in_plaintext->rw, (size_t) res)) {
            err = AH_EINTERN;
            goto handle_err;
        }

        cln->_conn_obs.cbs->on_read(cln->_conn_obs.ctx, conn, cln->_in_plaintext, AH_ENONE);
    }

    return;

handle_err:
    cln->_conn_obs.cbs->on_read(cln->_conn_obs.ctx, conn, NULL, err);
}

ah_err_t ah_i_mbedtls_conn_read_stop(void* cln_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_read_stop == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = cln->_trans.vtab->conn_read_stop(cln->_trans.ctx, conn);
    if (err != AH_ENONE) {
        return err;
    }

    ah_tcp_in_free(cln->_in_plaintext);

    return AH_ENONE;
}

ah_err_t ah_i_mbedtls_conn_write(void* cln_, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || conn == NULL || out == NULL) {
        return AH_EINVAL;
    }

    struct s_send_queue_entry* entry = ah_i_ring_alloc(&cln->_out_queue_ciphertext);
    if (entry == NULL) {
        return AH_ENOMEM;
    }
    entry->_kind = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_NORMAL;
    entry->_state = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_PENDING;

    int res = mbedtls_ssl_write(&cln->_ssl, out->buf.base, out->buf.size);
    if (res < 0) {
        switch (res) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            return AH_ERECONN;

        case MBEDTLS_ERR_SSL_WANT_WRITE:
            return AH_ENONE;

        default:
            return ah_i_mbedtls_res_to_err(&cln->_errs, res);
        }
    }

    // We guarantee that all data in out is written every time.
    if (out->buf.size != (size_t) res) {
        return AH_EINTERN;
    }

    return AH_ENONE;
}

static void s_conn_on_write(void* cln_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    ah_mbedtls_client_t* cln = cln_;
    ah_assert_if_debug(cln != NULL && cln->_conn_obs.cbs != NULL && cln->_conn_obs.cbs->on_write != NULL);

    struct s_send_queue_entry* entry = ah_i_ring_peek(&cln->_out_queue_ciphertext);
    if (entry == NULL) {
        if (err == AH_ENONE) {
            err = AH_EINTERN;
        }
        goto handle_err;
    }

    entry->_state = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_SENT;

    if (err != AH_ENONE) {
        goto handle_err;
    }

    if (entry->_kind == AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR) {
        ah_assert_if_debug(cln != NULL && cln->_trans.vtab != NULL && cln->_trans.vtab->conn_shutdown != NULL);
        err = cln->_trans.vtab->conn_shutdown(cln->_trans.ctx, conn, AH_TCP_SHUTDOWN_WR);
        switch (err) {
        case AH_ENONE:
            return;

        case AH_EINVAL:
            err = AH_EINTERN;
            goto handle_err;

        case AH_ESTATE:
            // Since we were able to write something (this code is in the write
            // completion callback), it must be that the connection has been
            // closed. If so, we consider our job done and return.
            return;

        default:
            goto handle_err;
        }
    }
    else if (entry->_kind == AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_CLOSE) {
        ah_assert_if_debug(cln != NULL && cln->_trans.vtab != NULL && cln->_trans.vtab->conn_close != NULL);
        cln->_conn = NULL;
        err = cln->_trans.vtab->conn_close(cln->_trans.ctx, conn);
        switch (err) {
        case AH_ENONE:
            return;

        case AH_EINVAL:
            err = AH_EINTERN;
            goto handle_err;

        case AH_ESTATE:
            // Already closed. We're done!
            return;

        default:
            goto handle_err;
        }
    }

    if (!cln->_is_handshake_done) {
        s_client_handshake(cln);
        return;
    }

    // Make MbedTLS aware that we have finished sending out->buf.
    int res = mbedtls_ssl_write(&cln->_ssl, out->buf.base, out->buf.size);
    if (res < 0) {
        if (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE) {
            cln->_is_handshake_done = false;
        }
        else {
            err = ah_i_mbedtls_res_to_err(&cln->_errs, res);
        }
    }
    else {
        if (((size_t) res) != out->buf.size) {
            err = AH_EINTERN;
        }
    }

handle_err:
    cln->_conn_obs.cbs->on_write(cln->_conn_obs.ctx, conn, out, err);
}

ah_err_t ah_i_mbedtls_conn_shutdown(void* cln_, ah_tcp_conn_t* conn, uint8_t flags)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_shutdown == NULL || conn == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    if (ah_tcp_conn_is_writable(conn) && (flags & AH_TCP_SHUTDOWN_WR) != 0) {
        err = s_client_close_notify(cln, AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR);
        if (err != AH_ENONE) {
            return err;
        }
    }

    if (ah_tcp_conn_is_readable(conn) && (flags & AH_TCP_SHUTDOWN_RD) != 0) {
        err = cln->_trans.vtab->conn_shutdown(cln->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
        if (err != AH_ENONE) {
            return err;
        }
    }

    return AH_ENONE;
}

static ah_err_t s_client_close_notify(ah_mbedtls_client_t* cln, uint8_t kind)
{
    ah_assert_if_debug(cln != NULL);

    struct s_send_queue_entry* entry = ah_i_ring_alloc(&cln->_out_queue_ciphertext);
    if (entry == NULL) {
        return AH_ENOMEM;
    }
    entry->_kind = kind;
    entry->_state = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_PENDING;

    int res = mbedtls_ssl_close_notify(&cln->_ssl);
    if (res == 0 || res == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return AH_ENONE;
    }
    return ah_i_mbedtls_res_to_err(&cln->_errs, res);
}

ah_err_t ah_i_mbedtls_conn_close(void* cln_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_close == NULL || conn == NULL) {
        return AH_EINVAL;
    }

    if (ah_tcp_conn_is_writable(conn)) {
        return s_client_close_notify(cln, AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_CLOSE);
    }

    cln->_conn = NULL;

    return cln->_trans.vtab->conn_close(cln->_trans.ctx, conn);
}

static void s_conn_on_close(void* cln_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* cln = cln_;
    ah_assert_if_debug(cln != NULL && cln->_conn_obs.cbs != NULL && cln->_conn_obs.cbs->on_close != NULL);
    cln->_conn_obs.cbs->on_close(cln->_conn_obs.ctx, conn, err);
}

ah_err_t ah_i_mbedtls_conn_term(void* cln_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_term == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = cln->_trans.vtab->conn_term(cln->_trans.ctx, conn);

    if (err != AH_EINVAL && err != AH_ESTATE) {
        ah_tcp_in_free(cln->_in_plaintext);
        if (cln->_server != NULL) {
            ah_mbedtls_client_term(cln);
        }
    }

    return err;
}

int ah_i_mbedtls_conn_get_family(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_get_family == NULL) {
        return -1;
    }
    return cln->_trans.vtab->conn_get_family(cln->_trans.ctx, conn);
}

ah_err_t ah_i_mbedtls_conn_get_laddr(void* cln_, const ah_tcp_conn_t* conn, ah_sockaddr_t* laddr)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_get_laddr == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_get_laddr(cln->_trans.ctx, conn, laddr);
}

ah_err_t ah_i_mbedtls_conn_get_raddr(void* cln_, const ah_tcp_conn_t* conn, ah_sockaddr_t* raddr)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_get_raddr == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_get_raddr(cln->_trans.ctx, conn, raddr);
}

ah_loop_t* ah_i_mbedtls_conn_get_loop(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_get_loop == NULL) {
        return NULL;
    }
    return cln->_trans.vtab->conn_get_loop(cln->_trans.ctx, conn);
}

void* ah_i_mbedtls_conn_get_obs_ctx(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_get_loop == NULL || conn == NULL) {
        return NULL;
    }
    return cln->_conn_obs.ctx;
}

bool ah_i_mbedtls_conn_is_closed(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_is_closed == NULL) {
        return true;
    }
    return cln->_trans.vtab->conn_is_closed(cln->_trans.ctx, conn);
}

bool ah_i_mbedtls_conn_is_readable(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_is_readable == NULL) {
        return false;
    }
    return cln->_trans.vtab->conn_is_readable(cln->_trans.ctx, conn);
}

bool ah_i_mbedtls_conn_is_reading(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_is_reading == NULL) {
        return false;
    }
    return cln->_trans.vtab->conn_is_reading(cln->_trans.ctx, conn);
}

bool ah_i_mbedtls_conn_is_writable(void* cln_, const ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_is_writable == NULL) {
        return false;
    }
    return cln->_trans.vtab->conn_is_writable(cln->_trans.ctx, conn);
}

ah_err_t ah_i_mbedtls_conn_set_keepalive(void* cln_, ah_tcp_conn_t* conn, bool is_enabled)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_set_keepalive == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_set_keepalive(cln->_trans.ctx, conn, is_enabled);
}

ah_err_t ah_i_mbedtls_conn_set_nodelay(void* cln_, ah_tcp_conn_t* conn, bool is_enabled)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_set_nodelay == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_set_nodelay(cln->_trans.ctx, conn, is_enabled);
}

ah_err_t ah_i_mbedtls_conn_set_reuseaddr(void* cln_, ah_tcp_conn_t* conn, bool is_enabled)
{
    ah_mbedtls_client_t* cln = cln_;
    if (cln == NULL || cln->_trans.vtab == NULL || cln->_trans.vtab->conn_set_reuseaddr == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans.vtab->conn_set_reuseaddr(cln->_trans.ctx, conn, is_enabled);
}
