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
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

typedef struct s_tls_ctx {
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;

    ah_tcp_trans_t trans;
} s_tls_ctx_t;

static ah_err_t s_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr);
static ah_err_t s_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr);
static ah_err_t s_conn_write(ah_tcp_conn_t* conn, ah_tcp_msg_t* msg);
static ah_err_t s_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags);
static ah_err_t s_conn_close(ah_tcp_conn_t* conn);

static s_tls_ctx_t* s_get_ctx_from_conn(ah_tcp_conn_t* conn);

static ah_err_t s_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab);
static ah_err_t s_listener_close(ah_tcp_listener_t* ln);

int s_ssl_send(void* ctx, const unsigned char* buf, size_t len);
int s_ssl_recv(void* ctx, unsigned char* buf, size_t len);

ah_extern ah_tcp_trans_t ah_tls_trans_using(ah_tcp_trans_t trans, ah_tls_ctx_t* ctx)
{
    if (ctx == NULL) {
        return trans;
    }

    s_tls_ctx_t* ctx0 = ctx->_impl;
    ah_assert_if_debug(ctx0 != NULL);

    ctx0->trans = trans;

    static const ah_tcp_trans_vtab_t s_vtab = {
        .conn_open = s_conn_open,
        .conn_connect = s_conn_connect,
        .conn_read_start = ah_tcp_conn_read_start,
        .conn_read_stop = ah_tcp_conn_read_stop,
        .conn_write = s_conn_write,
        .conn_shutdown = s_conn_shutdown,
        .conn_close = s_conn_close,

        .listener_open = ah_tcp_listener_open,
        .listener_listen = s_listener_listen,
        .listener_close = s_listener_close,
    };

    return (ah_tcp_trans_t) {
        .vtab = &s_vtab,
        .data = ctx,
    };
}

static ah_err_t s_conn_open(ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    ah_err_t err = ah_tcp_conn_open(conn, laddr);

    if (err == AH_ENONE) {
        s_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
        (void) ctx;
    }

    return err;
}

static ah_err_t s_conn_connect(ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    s_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);
    (void) raddr;

    // TODO: Should this be here? Why not in the open function?
    mbedtls_ssl_set_bio(&ctx->ssl, conn, s_ssl_send, s_ssl_recv, NULL);

    return AH_EOPNOTSUPP;
}

static s_tls_ctx_t* s_get_ctx_from_conn(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    ah_tls_ctx_t* ctx = ah_tcp_conn_get_user_data(conn);
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(ctx->_impl != NULL);

    return ctx->_impl;
}

int s_ssl_send(void* ctx, const unsigned char* buf, size_t len)
{
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(buf != NULL || len == 0u);

    ah_tcp_conn_t* conn = ctx;

    (void) conn;
    // buf/len refer to an encrypted block of data that now needs to be sent to
    // the remote host.

    // I currently think that the appropriate behavior is for this function to
    // take one out of two states. In state A, the buffer is sent, its pointer
    // and length is saved, the state transitions to B and
    // MBEDTLS_ERR_SSL_WANT_WRITE is returned. In state B, buf/len are compared
    // with the last buf/len. If they do not match, return an appropriate error
    // code. If they do match, change state to A and return len.

    return 0; // TODO: What to return? MBEDTLS_ERR_SSL_WANT_WRITE?
}

int s_ssl_recv(void* ctx, unsigned char* buf, size_t len)
{
    ah_assert_if_debug(ctx != NULL);
    ah_assert_if_debug(buf != NULL || len == 0u);

    ah_tcp_conn_t* conn = ctx;

    (void) conn;
    // What does this function being invoked really signify? That there is room
    // in the decryption buffer? TODO: Figure out and implement this.

    return 0; // TODO: What to return? MBEDTLS_ERR_SSL_WANT_WRITE?
}

static ah_err_t s_conn_write(ah_tcp_conn_t* conn, ah_tcp_msg_t* msg)
{
    s_tls_ctx_t* ctx = s_get_ctx_from_conn(conn);

    ah_bufs_t bufs = ah_tcp_msg_unwrap(msg);
    for (size_t i = 0u; i < bufs.length; i += 1u) {
        ah_buf_t buf = bufs.items[i];
        int res = mbedtls_ssl_write(&ctx->ssl, ah_buf_get_base(&buf), ah_buf_get_size(&buf));
        switch (res) {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
        case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
        case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
            return AH_EAGAIN;
        }
    }

    return AH_ENONE;
}

static ah_err_t s_conn_shutdown(ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    (void) conn;
    (void) flags;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_conn_close(ah_tcp_conn_t* conn)
{
    (void) conn;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_listener_listen(ah_tcp_listener_t* ln, unsigned backlog, const ah_tcp_conn_vtab_t* conn_vtab)
{
    (void) ln;
    (void) backlog;
    (void) conn_vtab;
    return AH_EOPNOTSUPP;
}

static ah_err_t s_listener_close(ah_tcp_listener_t* ln)
{
    (void) ln;
    return AH_EOPNOTSUPP;
}
