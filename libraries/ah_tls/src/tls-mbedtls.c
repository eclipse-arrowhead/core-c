// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tls.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/internal/_ring-gen.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <string.h>

static ah_err_t s_conn_open(void* ctx_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
static ah_err_t s_conn_connect(void* ctx_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
static ah_err_t s_conn_read_start(void* ctx_, ah_tcp_conn_t* conn);
static ah_err_t s_conn_read_stop(void* ctx_, ah_tcp_conn_t* conn);
static ah_err_t s_conn_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_msg_t* msg);
static ah_err_t s_conn_shutdown(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
static ah_err_t s_conn_close(void* ctx_, ah_tcp_conn_t* conn);

static void s_conn_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_conn_on_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err);
static void s_conn_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_close(ah_tcp_conn_t* conn, ah_err_t err);

static const ah_tls_cert_t* s_cert_from_mbedtls(const mbedtls_x509_crt* crt);
static ah_err_t s_close_notify(ah_tls_ctx_t* ctx);
static void s_handshake(ah_tcp_conn_t* conn);

static ah_err_t s_listener_open(void* ctx_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
static ah_err_t s_listener_listen(void* ctx_, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
static ah_err_t s_listener_close(void* ctx_, ah_tcp_listener_t* ln);

static int s_ssl_send(void* conn_, const unsigned char* buf, size_t len);
static int s_ssl_recv(void* conn_, unsigned char* buf, size_t len);

static ah_err_t s_mbedtls_res_to_ah_err(ah_tls_ctx_t* ctx, int res);

AH_I_RING_GEN_ALLOC_ENTRY(static, s_send_queue, struct ah_i_tls_send_queue, ah_tcp_msg_t, 4u)
AH_I_RING_GEN_DISCARD(static, s_send_queue, struct ah_i_tls_send_queue)
AH_I_RING_GEN_INIT(static, s_send_queue, struct ah_i_tls_send_queue, ah_tcp_msg_t, 4u)
AH_I_RING_GEN_IS_EMPTY(static, s_send_queue, struct ah_i_tls_send_queue)
AH_I_RING_GEN_TERM(static, s_send_queue, struct ah_i_tls_send_queue)

static const ah_tcp_vtab_t s_conn_vtab = {
    .conn_open = s_conn_open,
    .conn_connect = s_conn_connect,
    .conn_read_start = s_conn_read_start,
    .conn_read_stop = s_conn_read_stop,
    .conn_write = s_conn_write,
    .conn_shutdown = s_conn_shutdown,
    .conn_close = s_conn_close,

    .listener_open = s_listener_open,
    .listener_listen = s_listener_listen,
    .listener_close = s_listener_close,
};

ah_extern ah_err_t ah_tls_ctx_init(ah_tls_ctx_t* ctx, ah_tcp_trans_t trans, ah_tls_cert_store_t* certs, ah_tls_on_handshake_done_cb on_handshake_done)
{
    if (ctx == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || certs == NULL || on_handshake_done == NULL) {
        return AH_EINVAL;
    }
    if ((certs->_own_chain == NULL) != (certs->_own_key == NULL)) {
        return AH_EINVAL;
    }
    if (certs->_own_chain == NULL && certs->_authorities == NULL) {
        return AH_EINVAL;
    }

    *ctx = (ah_tls_ctx_t) {
        ._trans = trans,
        ._certs = certs,
        ._on_handshake_done = on_handshake_done,
    };

    ah_err_t err = s_send_queue_init(&ctx->_send_ciphertext_queue);
    if (err != AH_ENONE) {
        return err;
    }

    int res;

    // Setup source of secure random numbers.
    mbedtls_entropy_init(&ctx->_entropy);
    mbedtls_ctr_drbg_init(&ctx->_ctr_drbg);
    res = mbedtls_ctr_drbg_seed(&ctx->_ctr_drbg, mbedtls_entropy_func, &ctx->_entropy, NULL, 0u);
    if (res != 0) {
        goto handle_non_zero_res;
    }

    // Initialize and setup configuration.
    mbedtls_ssl_config_init(&ctx->_ssl_conf);
    mbedtls_ssl_conf_ca_chain(&ctx->_ssl_conf, ctx->_certs->_authorities, ctx->_certs->_revocations);
    res = mbedtls_ssl_conf_own_cert(&ctx->_ssl_conf, certs->_own_chain, certs->_own_key);
    if (res != 0) {
        goto handle_non_zero_res;
    }
    mbedtls_ssl_conf_renegotiation(&ctx->_ssl_conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
    mbedtls_ssl_conf_rng(&ctx->_ssl_conf, mbedtls_ctr_drbg_random, &ctx->_ctr_drbg);

    // Initialize and setup SSL transport.
    mbedtls_ssl_init(&ctx->_ssl);
    res = mbedtls_ssl_setup(&ctx->_ssl, &ctx->_ssl_conf);
    if (res != 0) {
        goto handle_non_zero_res;
    }

    return AH_ENONE;

handle_non_zero_res:
    return s_mbedtls_res_to_ah_err(ctx, res);
}

static ah_err_t s_mbedtls_res_to_ah_err(ah_tls_ctx_t* ctx, int res)
{
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(res <= 0);

    switch (res) {
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
        if (ctx->_pending_ah_err != AH_ENONE) {
            ah_err_t err = ctx->_pending_ah_err;
            ctx->_pending_ah_err = AH_ENONE;
            return err;
        }
        // fallthrough
    default:
        ctx->_last_mbedtls_err = res;
        return AH_EDEP;
    }
}

ah_extern ah_tls_ctx_t* ah_tls_ctx_get_from_conn(ah_tcp_conn_t* conn)
{
    if (conn == NULL || conn->_trans.vtab != &s_conn_vtab) {
        return NULL;
    }
    return conn->_trans.ctx;
}

ah_extern ah_tls_err_t ah_tls_ctx_get_last_error(ah_tls_ctx_t* ctx)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return ctx->_last_mbedtls_err;
}

ah_extern ah_tls_err_t ah_tls_ctx_get_last_error_from_conn(ah_tcp_conn_t* conn)
{
    return ah_tls_ctx_get_last_error(ah_tls_ctx_get_from_conn(conn));
}

ah_extern ah_tcp_trans_t ah_tls_ctx_as_trans(ah_tls_ctx_t* ctx)
{
    return (ah_tcp_trans_t) {
        .vtab = &s_conn_vtab,
        .ctx = ctx,
    };
}

static ah_err_t s_conn_open(void* ctx_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    static const ah_tcp_conn_cbs_t s_cbs = {
        .on_open = s_conn_on_open,
        .on_connect = s_conn_on_connect,
        .on_read_alloc = s_conn_on_read_alloc,
        .on_read_data = s_conn_on_read_data,
        .on_write_done = s_conn_on_write_done,
        .on_close = s_conn_on_close,
    };

    ctx->_conn_cbs = conn->_cbs;
    conn->_cbs = &s_cbs;

    int res;

    const int endpoint = MBEDTLS_SSL_IS_CLIENT;
    const int transport = MBEDTLS_SSL_TRANSPORT_STREAM;
    const int preset = MBEDTLS_SSL_PRESET_DEFAULT;
    res = mbedtls_ssl_config_defaults(&ctx->_ssl_conf, endpoint, transport, preset);
    if (res != 0) {
        goto handle_non_zero_res;
    }

    mbedtls_ssl_set_bio(&ctx->_ssl, conn, s_ssl_send, s_ssl_recv, NULL);

    if (ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_open == NULL) {
        return AH_ESTATE;
    }
    return ctx->_trans.vtab->conn_open(ctx->_trans.ctx, conn, laddr);

handle_non_zero_res:
    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return AH_ENOMEM;
    }
    ctx->_last_mbedtls_err = res;
    return AH_EDEP;
}

// Called with encrypted data to have it sent.
static int s_ssl_send(void* conn_, const unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_tcp_conn_t* conn = conn_;

    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);
    if (ctx == NULL) {
        err = AH_ESTATE;
        goto handle_err;
    }

    if (conn == NULL || (buf == NULL && len != 0u)) {
        err = AH_ESTATE;
        goto handle_err;
    }

    if (len > INT_MAX) {
        err = AH_EOVERFLOW;
        goto handle_err;
    }

    ah_tcp_msg_t* msg;
    err = s_send_queue_alloc_entry(&ctx->_send_ciphertext_queue, &msg);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    err = ah_buf_init(&msg->buf, (uint8_t*) buf, len);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    if (ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_write == NULL) {
        err = AH_ESTATE;
        goto handle_err;
    }
    err = ctx->_trans.vtab->conn_write(ctx->_trans.ctx, conn, msg);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return (int) len;

handle_err:
    ctx->_pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

// Called to get new unencrypted data, if available.
static int s_ssl_recv(void* conn_, unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_tcp_conn_t* conn = conn_;

    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);
    if (ctx == NULL) {
        err = AH_ESTATE;
        goto handle_err;
    }

    if (conn == NULL || (buf == NULL && len != 0u)) {
        err = AH_ESTATE;
        goto handle_err;
    }

    size_t n_available_bytes = ah_buf_get_size(&ctx->_recv_ciphertext_buf);
    if (n_available_bytes == 0u) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (len > n_available_bytes) {
        len = n_available_bytes;
    }
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    memcpy(buf, ah_buf_get_base(&ctx->_recv_ciphertext_buf), len);

    ah_buf_skipn(&ctx->_recv_ciphertext_buf, len);

    return (int) len;

handle_err:
    ctx->_pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

static ah_err_t s_conn_connect(void* ctx_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL || ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_connect == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }
    return ctx->_trans.vtab->conn_connect(ctx->_trans.ctx, conn, raddr);
}

static ah_err_t s_conn_read_start(void* ctx_, ah_tcp_conn_t* conn)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL || ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_read_start == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (!ctx->_is_handshake_done) {
        ctx->_is_stopping_reads_on_handshake_completion = false;
        return AH_ENONE;
    }

    return ctx->_trans.vtab->conn_read_start(ctx->_trans.ctx, conn);
}

static ah_err_t s_conn_read_stop(void* ctx_, ah_tcp_conn_t* conn)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL || ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_read_stop == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (!ctx->_is_handshake_done) {
        ctx->_is_stopping_reads_on_handshake_completion = true;
        return AH_ENONE;
    }

    return ctx->_trans.vtab->conn_read_stop(ctx->_trans.ctx, conn);
}

static ah_err_t s_conn_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_msg_t* msg)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    int res = mbedtls_ssl_write(&ctx->_ssl, ah_buf_get_base(&msg->buf), ah_buf_get_size(&msg->buf));

    if (res < 0) {
        return s_mbedtls_res_to_ah_err(ctx, res);
    }

    // We guarantee that all of msg is written every time.
    ah_assert_if_debug(ah_buf_get_size(&msg->buf) == (size_t) res);

    return AH_ENONE;
}

static ah_err_t s_conn_shutdown(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL || ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_shutdown == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    if (ah_tcp_conn_is_writable(conn) && (flags & AH_TCP_SHUTDOWN_WR) != 0) {
        err = s_close_notify(ctx);
        if (err != AH_ENONE) {
            return err;
        }
        ctx->_is_shutting_down_wr_on_next_write_done = true;
    }

    if (ah_tcp_conn_is_readable(conn) && (flags & AH_TCP_SHUTDOWN_RD) != 0) {
        err = ctx->_trans.vtab->conn_shutdown(ctx->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
        if (err != AH_ENONE) {
            return err;
        }
    }

    return AH_ENONE;
}

static ah_err_t s_close_notify(ah_tls_ctx_t* ctx)
{
    ah_assert_if_debug(ctx != NULL);

    int res = mbedtls_ssl_close_notify(&ctx->_ssl);

    if (res < 0) {
        return s_mbedtls_res_to_ah_err(ctx, res);
    }

    return AH_ENONE;
}

static ah_err_t s_conn_close(void* ctx_, ah_tcp_conn_t* conn)
{
    ah_tls_ctx_t* ctx = ctx_;
    if (ctx == NULL || ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_close == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (ah_tcp_conn_is_writable(conn)) {
        ah_err_t err = s_close_notify(ctx);

        if (err == AH_ENONE) {
            ctx->_is_closing_on_next_write_done = true;
        }

        return err;
    }

    return ctx->_trans.vtab->conn_close(ctx->_trans.ctx, conn);
}

static void s_conn_on_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);
    ctx->_conn_cbs->on_open(conn, err);
}

static void s_conn_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);

    ctx->_is_stopping_reads_on_handshake_completion = true;
    ctx->_conn_cbs->on_connect(conn, err);

    if (ah_tcp_conn_is_readable_and_writable(conn)) {
        s_handshake(conn);
    }
}

static void s_handshake(ah_tcp_conn_t* conn)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);

    int res;
    ah_err_t err;

    res = mbedtls_ssl_handshake(&ctx->_ssl);

    switch (res) {
    case 0:
        ctx->_is_handshake_done = true;

        if (ctx->_is_stopping_reads_on_handshake_completion) {
            ctx->_is_stopping_reads_on_handshake_completion = false;
            err = ah_tcp_conn_read_stop(conn);
            if (err != AH_ENONE) {
                err = AH_EINTERN;
                break;
            }
        }

        ctx->_on_handshake_done(conn, s_cert_from_mbedtls(mbedtls_ssl_get_peer_cert(&ctx->_ssl)), AH_ENONE);

        return;

    case MBEDTLS_ERR_SSL_WANT_READ:
        ctx->_is_handshaking_on_next_read_data = true;
        if (ah_tcp_conn_is_reading(conn)) {
            return;
        }
        err = ah_tcp_conn_read_start(conn);
        break;

    case MBEDTLS_ERR_SSL_WANT_WRITE:
        // As of MbedTLS versions 2.28.0 and 3.1.0, this result code is only
        // possible if either of the send or receive callbacks set via
        // mbedtls_ssl_set_bio() return it. None of our callbacks (s_ssl_recv()
        // and s_ssl_send()) do. We, therefore, hope that this behavior will
        // remain consistent across future versions and treat the occurrence of
        // this result code as an internal error.
        err = AH_EINTERN;
        break;

    case MBEDTLS_ERR_ERROR_GENERIC_ERROR:
        if (ctx->_pending_ah_err != AH_ENONE) {
            err = ctx->_pending_ah_err;
            ctx->_pending_ah_err = AH_ENONE;
            break;
        }
        // fallthrough

    default:
        ctx->_last_mbedtls_err = res;
        err = AH_EDEP;
        break;
    }

    ctx->_on_handshake_done(conn, NULL, err);
}

static const ah_tls_cert_t* s_cert_from_mbedtls(const mbedtls_x509_crt* crt)
{
    return (const ah_tls_cert_t*) crt;
}

static void s_conn_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);
    ctx->_conn_cbs->on_read_alloc(conn, buf);
}

static void s_conn_on_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);

    if (err != AH_ENONE) {
        goto handle_err;
    }

    ctx->_recv_ciphertext_buf = buf;
    ah_buf_limit_size_to(&ctx->_recv_ciphertext_buf, nread);

    int res;

    if (ctx->_is_handshaking_on_next_read_data) {
        ctx->_is_handshaking_on_next_read_data = false;

        s_handshake(conn);

        if (!ah_tcp_conn_is_readable(conn)) {
            return;
        }
    }

    while (ah_buf_get_size(&ctx->_recv_ciphertext_buf) > 0u) {
        ah_buf_t recv_plaintext_buf = (ah_buf_t) { 0u };
        conn->_cbs->on_read_alloc(conn, &recv_plaintext_buf);

        if (ah_buf_is_empty(&recv_plaintext_buf)) {
            err = AH_ENOBUFS;
            goto handle_err;
        }

        // This call will make MbedTLS pull the ciphertext in `ctx->_recv_ciphertext_buf` through the appropriate
        // decryption algorithms and write any resulting plaintext to `recv_plaintext_buf`. See also `s_ssl_recv()`.
        res = mbedtls_ssl_read(&ctx->_ssl, ah_buf_get_base(&recv_plaintext_buf), ah_buf_get_size(&recv_plaintext_buf));

        if (res <= 0) {
            switch (res) {
            case 0:
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                err = ctx->_trans.vtab->conn_shutdown(ctx->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
                if (err == AH_ESTATE || err == AH_ENOTCONN) {
                    return;
                }
                if (err == AH_ENONE) {
                    err = AH_EEOF;
                }
                goto handle_err;

            case MBEDTLS_ERR_SSL_WANT_READ:
                // When more data becomes available, this function will be
                // called again, and, consequently, so will mbedtls_ssl_read().
                return;

            case MBEDTLS_ERR_SSL_WANT_WRITE:
                // See MBEDTLS_ERR_SSL_WANT_WRITE case in s_handshake().
                err = AH_EINTERN;
                goto handle_err;

            default:
                ctx->_last_mbedtls_err = res;
                err = AH_EDEP;
                goto handle_err;
            }
        }

        ctx->_conn_cbs->on_read_data(conn, recv_plaintext_buf, (size_t) res, AH_ENONE);
    }

handle_err:
    ctx->_conn_cbs->on_read_data(conn, (ah_buf_t) { 0u }, 0u, err);
}

static void s_conn_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);

    if (err != AH_ENONE) {
        goto handle_err;
    }

    if (ctx->_is_shutting_down_wr_on_next_write_done) {
        ctx->_is_shutting_down_wr_on_next_write_done = false;

        ah_assert_if_debug(ctx->_trans.vtab != NULL);
        ah_assert_if_debug(ctx->_trans.vtab->conn_shutdown != NULL);

        err = ctx->_trans.vtab->conn_shutdown(ctx->_trans.ctx, conn, AH_TCP_SHUTDOWN_WR);
        switch (err) {
        case AH_ENONE:
            return;

        case AH_EINVAL:
            err = AH_EINTERN;
            goto handle_err;

        case AH_ESTATE:
            // Since we were able to write something (this code is in the write
            // completion callback), it must be that the connection has been
            // closed. If so, then we can consider our job done and return.
            return;

        default:
            goto handle_err;
        }
    }

    if (ctx->_is_closing_on_next_write_done) {
        ctx->_is_closing_on_next_write_done = false;

        ah_assert_if_debug(ctx->_trans.vtab != NULL);
        ah_assert_if_debug(ctx->_trans.vtab->conn_close != NULL);

        err = ctx->_trans.vtab->conn_close(ctx->_trans.ctx, conn);
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

    if (s_send_queue_is_empty(&ctx->_send_ciphertext_queue)) {
        err = AH_EINTERN;
        goto handle_err;
    }

    s_send_queue_discard(&ctx->_send_ciphertext_queue);

handle_err:
    ctx->_conn_cbs->on_write_done(conn, err);
}

static void s_conn_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = ah_tls_ctx_get_from_conn(conn);

    s_send_queue_term(&ctx->_send_ciphertext_queue);

    ctx->_conn_cbs->on_close(conn, err);
}

static ah_err_t s_listener_open(void* ctx_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr)
{
    (void) ctx_;
    (void) ln;
    (void) laddr;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_listener_listen(void* ctx_, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs)
{
    (void) ctx_;
    (void) ln;
    (void) backlog;
    (void) conn_cbs;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_listener_close(void* ctx_, ah_tcp_listener_t* ln)
{
    (void) ctx_;
    (void) ln;
    return AH_EOPNOTSUPP;
}

ah_extern void ah_tls_ctx_term(ah_tls_ctx_t* ctx)
{
    ah_assert_if_debug(ctx != NULL);

    mbedtls_ctr_drbg_free(&ctx->_ctr_drbg);
    mbedtls_entropy_free(&ctx->_entropy);
    mbedtls_ssl_free(&ctx->_ssl);
    mbedtls_ssl_cache_free(&ctx->_ssl_cache);
    mbedtls_ssl_config_free(&ctx->_ssl_conf);
}
