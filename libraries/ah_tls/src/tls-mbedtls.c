// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tls.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>

#define S_STATE_SHUTTING_DOWN_RDWR 0x01
#define S_STATE_SHUTTING_DOWN_WR   0x02
#define S_STATE_CLOSING            0x03
#define S_STATE_CLOSED             0x00

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

static ah_err_t s_close_notify(ah_tls_ctx_t* ctx, ah_tcp_conn_t* conn, unsigned next_state);

static ah_tls_ctx_t* s_cast_ctx(void* ctx);
static ah_tls_ctx_t* s_get_ctx_from_conn(ah_tcp_conn_t* conn);

static ah_err_t s_listener_open(void* ctx_, ah_tcp_listener_t* ln, const ah_sockaddr_t* laddr);
static ah_err_t s_listener_listen(void* ctx_, ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_cbs_t* conn_cbs);
static ah_err_t s_listener_close(void* ctx_, ah_tcp_listener_t* ln);

int s_ssl_send(void* conn_, const unsigned char* buf, size_t len);
int s_ssl_recv(void* conn_, unsigned char* buf, size_t len);

ah_extern ah_err_t ah_tls_ctx_init(ah_tls_ctx_t* ctx, ah_tcp_trans_t trans, ah_tls_cert_store_t* certs)
{
    if (ctx == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || certs == NULL) {
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
        ._state = S_STATE_CLOSED,
    };

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
    mbedtls_ssl_conf_rng(&ctx->_ssl_conf, mbedtls_ctr_drbg_random, &ctx->_ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&ctx->_ssl_conf, ctx->_certs->_authorities, ctx->_certs->_revocations);
    res = mbedtls_ssl_conf_own_cert(&ctx->_ssl_conf, certs->_own_chain, certs->_own_key);
    if (res != 0) {
        goto handle_non_zero_res;
    }

    // Initialize and setup SSL transport.
    mbedtls_ssl_init(&ctx->_ssl);
    res = mbedtls_ssl_setup(&ctx->_ssl, &ctx->_ssl_conf);
    if (res != 0) {
        goto handle_non_zero_res;
    }

    return AH_ENONE;

handle_non_zero_res:
    if (res == MBEDTLS_ERR_SSL_ALLOC_FAILED) {
        return AH_ENOMEM;
    }
    ctx->_last_mbedtls_err = res;
    return AH_EINTERN;
}

ah_extern ah_tls_err_t ah_tls_ctx_get_last_error(ah_tls_ctx_t* ctx)
{
    ah_assert(ctx != NULL);

    return ctx->_last_mbedtls_err;
}

ah_extern ah_tcp_trans_t ah_tls_ctx_get_transport(ah_tls_ctx_t* ctx)
{
    ah_assert(ctx != NULL);

    static const ah_tcp_vtab_t s_vtab = {
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

    return (ah_tcp_trans_t) {
        .vtab = &s_vtab,
        .ctx = ctx,
    };
}

static ah_err_t s_conn_open(void* ctx_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    ah_tls_ctx_t* ctx = s_cast_ctx(ctx_);

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

    return ctx->_trans.vtab->conn_open(ctx->_trans.ctx, conn, laddr);

handle_non_zero_res:
    if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
        return AH_ENOMEM;
    }
    ctx->_last_mbedtls_err = res;
    return AH_EDEP;
}

static ah_tls_ctx_t* s_cast_ctx(void* ctx)
{
    ah_assert_if_debug(ctx != NULL);
    return ctx;
}

static ah_err_t s_conn_connect(void* ctx_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    ah_tls_ctx_t* ctx = s_cast_ctx(ctx_);

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_connect == NULL) {
        return AH_EINVAL;
    }
    return ctx->_trans.vtab->conn_connect(ctx->_trans.ctx, conn, raddr);
}

// Called with encrypted data to have it sent.
int s_ssl_send(void* conn_, const unsigned char* buf, size_t len)
{
    ah_tcp_conn_t* conn = conn_;

    if (conn == NULL || (buf == NULL && len != 0u)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);

    if (len > INT_MAX) {
        ctx->_pending_ah_err = AH_EOVERFLOW;
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_write == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    ah_tcp_msg_t* msg = NULL; // TODO: buf and len to newly allocated msg. Free msg in on_write_done callback.

    ah_err_t err = ctx->_trans.vtab->conn_write(ctx->_trans.ctx, conn, msg);
    if (err != AH_ENONE) {
        ctx->_pending_ah_err = err;
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }

    return (int) len;
}

static ah_tls_ctx_t* s_get_ctx_from_conn(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    return s_cast_ctx(conn->_trans.ctx);
}

// Called to get new unencrypted data, if available.
int s_ssl_recv(void* conn_, unsigned char* buf, size_t len)
{
    ah_assert_if_debug(conn_ != NULL);
    ah_assert_if_debug(buf != NULL || len == 0u);

    ah_tcp_conn_t* conn = conn_;

    (void) conn;
    // What does this function being invoked really signify? That there is room
    // in the decryption buffer? TODO: Figure out and implement this.

    return 0; // TODO: What to return? MBEDTLS_ERR_SSL_WANT_READ?
}

static ah_err_t s_conn_read_start(void* ctx_, ah_tcp_conn_t* conn)
{
    (void) ctx_;
    (void) conn;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_conn_read_stop(void* ctx_, ah_tcp_conn_t* conn)
{
    (void) ctx_;
    (void) conn;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_conn_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_msg_t* msg)
{
    ah_tls_ctx_t* ctx = s_cast_ctx(ctx_);

    if (conn == NULL) {
        return AH_EINVAL;
    }
    if (conn->_trans.vtab == NULL || conn->_trans.vtab->conn_write == NULL) {
        return AH_EINVAL;
    }

    int res = mbedtls_ssl_write(&ctx->_ssl, ah_buf_get_base(&msg->buf), ah_buf_get_size(&msg->buf));
    if (res >= 0) {
        return AH_ENONE;
    }

    switch (res) {
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
    case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
    case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
        // TODO: Save state indicating that this write should be retried after the next read.
        return AH_ENONE;

    default:
        ctx->_last_mbedtls_err = res; // TODO: Check if any more result codes can be converted to ah_err_t errors.
        return AH_EDEP;
    }
}

static ah_err_t s_conn_shutdown(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    ah_tls_ctx_t* ctx = s_cast_ctx(ctx_);

    if ((flags & AH_TCP_SHUTDOWN_WR) != 0) {
        unsigned next_state = flags == AH_TCP_SHUTDOWN_RDWR ? S_STATE_SHUTTING_DOWN_RDWR : S_STATE_SHUTTING_DOWN_WR;
        return s_close_notify(ctx, conn, next_state);
    }

    if (ctx->_trans.vtab == NULL || ctx->_trans.vtab->conn_shutdown == NULL) {
        return AH_ESTATE;
    }
    return ctx->_trans.vtab->conn_shutdown(ctx->_trans.ctx, conn, flags);
}

static ah_err_t s_close_notify(ah_tls_ctx_t* ctx, ah_tcp_conn_t* conn, unsigned next_state)
{
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(conn != NULL);

    int res = mbedtls_ssl_close_notify(&ctx->_ssl);
    switch (res) {
    case 0:
    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        ctx->_state = next_state;
        return AH_ENONE;

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

static ah_err_t s_conn_close(void* ctx_, ah_tcp_conn_t* conn)
{
    return s_close_notify(ctx_, conn, S_STATE_CLOSING);
}

static void s_conn_on_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
    ctx->_conn_cbs->on_open(conn, err);
}

static void s_conn_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
    ctx->_conn_cbs->on_connect(conn, err);
}

static void s_conn_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
    ctx->_conn_cbs->on_read_alloc(conn, buf);
}

static void s_conn_on_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err)
{
    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);

    switch (ctx->_state) {

    }

    ctx->_conn_cbs->on_read_data(conn, buf, nread, err);
}

static void s_conn_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
    ctx->_conn_cbs->on_write_done(conn, err);
}

static void s_conn_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
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
