// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
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

#define S_SEND_QUEUE_ENTRY_KIND_NORMAL      0u
#define S_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR 1u
#define S_SEND_QUEUE_ENTRY_KIND_CLOSE       2u

struct ah_i_mbedtls_send_queue_entry {
    unsigned kind;
    struct ah_tcp_out out;
};

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err);

static ah_err_t s_close_notify(ah_mbedtls_client_t* client);

const ah_tcp_conn_cbs_t ah_i_mbedtls_tcp_conn_cbs = {
    .on_open = s_on_open,
    .on_connect = s_on_connect,
    .on_read_alloc = s_on_read_alloc,
    .on_read = s_on_read_data_,
    .on_write = s_on_write_done,
    .on_close = s_on_close,
};

ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (client == NULL || !ah_tcp_vtab_is_valid(trans.vtab) || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    return ah_i_mbedtls_client_init(client, trans, ssl_conf, on_handshake_done_cb);
}

ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* client)
{
    ah_assert(client != NULL);

    return client->_errs._last_mbedtls_err;
}

ah_extern mbedtls_ssl_context* ah_mbedtls_client_get_ssl_context(ah_mbedtls_client_t* client)
{
    ah_assert(client != NULL);

    return &client->_ssl;
}

ah_extern ah_tcp_trans_t ah_mbedtls_client_as_trans(ah_mbedtls_client_t* client)
{
    return (ah_tcp_trans_t) {
        .vtab = &ah_i_mbedtls_tcp_vtab,
        .ctx = client,
    };
}

ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* client)
{
    ah_assert(client != NULL);

    mbedtls_ssl_free(&client->_ssl);
    ah_i_ring_term(&client->_send_ciphertext_queue);

    if (client->_server != NULL) {
        ah_i_tls_server_free_accepted_client(client->_server, client);
    }
}

ah_extern ah_mbedtls_client_t* ah_mbedtls_conn_get_client(ah_tcp_conn_t* conn)
{
    if (conn == NULL || conn->_trans.vtab != &ah_i_mbedtls_tcp_vtab) {
        return NULL;
    }
    return conn->_trans.ctx;
}

ah_extern int ah_mbedtls_conn_get_last_err(ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);
    if (client == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return ah_mbedtls_client_get_last_err(client);
}

ah_extern mbedtls_ssl_context* ah_mbedtls_conn_get_ssl_context(ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);
    if (client == NULL) {
        return NULL;
    }
    return ah_mbedtls_client_get_ssl_context(client);
}

ah_err_t ah_i_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    ah_assert_if_debug(client != NULL);
    ah_assert_if_debug(ah_tcp_vtab_is_valid(trans.vtab));
    ah_assert_if_debug(ssl_conf != NULL);
    ah_assert_if_debug(on_handshake_done_cb != NULL);

    int res;

    *client = (ah_mbedtls_client_t) {
        ._trans = trans,
        ._on_handshake_done_cb = on_handshake_done_cb,
    };

    ah_err_t err = ah_i_ring_init(&client->_send_ciphertext_queue, 4u, sizeof(struct ah_i_mbedtls_send_queue_entry));
    if (err != AH_ENONE) {
        return err;
    }

    mbedtls_ssl_init(&client->_ssl);
    res = mbedtls_ssl_setup(&client->_ssl, ssl_conf);
    if (res != 0) {
        goto handle_non_zero_res;
    }

    return AH_ENONE;

handle_non_zero_res:
    return ah_i_mbedtls_res_to_err(&client->_errs, res);
}

ah_err_t ah_i_mbedtls_client_open(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    client->_conn_cbs = conn->_cbs;
    conn->_cbs = &ah_i_mbedtls_tcp_conn_cbs;

    mbedtls_ssl_set_bio(&client->_ssl, conn, ah_i_mbedtls_ssl_on_send, ah_i_mbedtls_ssl_on_recv, NULL);

    if (client->_trans.vtab == NULL || client->_trans.vtab->conn_open == NULL) {
        return AH_ESTATE;
    }
    return client->_trans.vtab->conn_open(client->_trans.ctx, conn, laddr);
}

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_open(conn, AH_ESTATE);
        return;
    }

    client->_conn_cbs->on_open(conn, err);
}

ah_err_t ah_i_mbedtls_client_connect(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_connect == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }
    return client->_trans.vtab->conn_connect(client->_trans.ctx, conn, raddr);
}

static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_connect(conn, AH_ESTATE);
        return;
    }

    client->_is_stopping_reads_on_handshake_completion = true;
    client->_conn_cbs->on_connect(conn, err);

    if (ah_tcp_conn_is_readable_and_writable(conn)) {
        ah_i_mbedtls_handshake(conn);
    }
}

ah_err_t ah_i_mbedtls_client_read_start(void* client_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_read_start == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (!client->_is_handshake_done) {
        client->_is_stopping_reads_on_handshake_completion = false;
        return AH_ENONE;
    }

    return client->_trans.vtab->conn_read_start(client->_trans.ctx, conn);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_read(conn, (ah_buf_t) { 0u }, 0u, AH_ESTATE);
        return;
    }

    client->_conn_cbs->on_read_alloc(conn, buf);
}

static void s_on_read_data(ah_tcp_conn_t* conn, ah_buf_t buf, size_t nread, ah_err_t err)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_read(conn, (ah_buf_t) { 0u }, 0u, AH_ESTATE);
        return;
    }

    if (err != AH_ENONE) {
        goto handle_err;
    }

    client->_recv_ciphertext_buf = buf;
    ah_buf_limit_size_to(&client->_recv_ciphertext_buf, nread);

    int res;

    if (client->_is_handshaking_on_next_read_data) {
        client->_is_handshaking_on_next_read_data = false;

        ah_i_mbedtls_handshake(conn);

        if (!ah_tcp_conn_is_readable(conn)) {
            return;
        }
    }

    while (ah_buf_get_size(&client->_recv_ciphertext_buf) > 0u) {
        ah_buf_t recv_plaintext_buf = (ah_buf_t) { 0u };
        client->_conn_cbs->on_read_alloc(conn, &recv_plaintext_buf);

        if (ah_buf_is_empty(&recv_plaintext_buf)) {
            err = AH_ENOBUFS;
            goto handle_err;
        }

        // This call will make MbedTLS pull the ciphertext in `client->_recv_ciphertext_buf` through the appropriate
        // decryption algorithms and write any resulting plaintext to `recv_plaintext_buf`. See also `s_ssl_recv()`.
        res = mbedtls_ssl_read(&client->_ssl, ah_buf_get_base(&recv_plaintext_buf), ah_buf_get_size(&recv_plaintext_buf));

        if (res <= 0) {
            switch (res) {
            case 0:
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                err = client->_trans.vtab->conn_shutdown(client->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
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
                client->_errs._last_mbedtls_err = res;
                err = AH_EDEP;
                goto handle_err;
            }
        }

        client->_conn_cbs->on_read(conn, recv_plaintext_buf, (size_t) res, AH_ENONE);
    }

    return;

handle_err:
    client->_conn_cbs->on_read(conn, (ah_buf_t) { 0u }, 0u, err);
}

ah_err_t ah_i_mbedtls_client_read_stop(void* client_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_read_stop == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (!client->_is_handshake_done) {
        client->_is_stopping_reads_on_handshake_completion = true;
        return AH_ENONE;
    }

    return client->_trans.vtab->conn_read_stop(client->_trans.ctx, conn);
}

ah_err_t ah_i_mbedtls_client_write(void* client_, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    int res = mbedtls_ssl_write(&client->_ssl, ah_buf_get_base(&out->buf), ah_buf_get_size(&out->buf));
    if (res == MBEDTLS_ERR_SSL_WANT_READ || res == MBEDTLS_ERR_SSL_WANT_WRITE) {
        ah_i_mbedtls_handshake(conn);
        return AH_ERECONN;
    }
    else if (res < 0) {
        return ah_i_mbedtls_res_to_err(&client->_errs, res);
    }

    // mbedtls_ssl_write() calls ah_i_mbedtls_ssl_on_send(), which adds a new entry of unset kind to the send queue.
    struct ah_i_mbedtls_send_queue_entry* entry = ah_i_ring_peek(&client->_send_ciphertext_queue);
    if (entry == NULL || entry->kind != S_SEND_QUEUE_ENTRY_KIND_NORMAL) {
        return AH_EINTERN;
    }
    entry->kind = S_SEND_QUEUE_ENTRY_KIND_NORMAL;

    // We guarantee that all of out is written every time.
    ah_assert_if_debug(ah_buf_get_size(&out->buf) == (size_t) res);

    return AH_ENONE;
}

static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_write(conn, AH_ESTATE);
        return;
    }

    struct ah_i_mbedtls_send_queue_entry* entry = ah_i_ring_peek(&client->_send_ciphertext_queue);
    if (entry == NULL) {
        if (err == AH_ENONE) {
            err = AH_EINTERN;
        }
        goto handle_err;
    }

    unsigned entry_kind = entry->kind;

    ah_i_ring_skip(&client->_send_ciphertext_queue);

    if (err != AH_ENONE) {
        goto handle_err;
    }

    if (entry_kind == S_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR) {
        ah_assert_if_debug(client->_trans.vtab != NULL);
        ah_assert_if_debug(client->_trans.vtab->conn_shutdown != NULL);

        err = client->_trans.vtab->conn_shutdown(client->_trans.ctx, conn, AH_TCP_SHUTDOWN_WR);
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
    else if (entry_kind == S_SEND_QUEUE_ENTRY_KIND_CLOSE) {
        ah_assert_if_debug(client->_trans.vtab != NULL);
        ah_assert_if_debug(client->_trans.vtab->conn_close != NULL);

        err = client->_trans.vtab->conn_close(client->_trans.ctx, conn);
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

    if (!client->_is_handshake_done) {
        ah_i_mbedtls_handshake(conn);
        return;
    }

handle_err:
    client->_conn_cbs->on_write(conn, err);
}

ah_err_t ah_i_mbedtls_client_shutdown(void* client_, ah_tcp_conn_t* conn, ah_tcp_shutdown_t flags)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_shutdown == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    if (ah_tcp_conn_is_writable(conn) && (flags & AH_TCP_SHUTDOWN_WR) != 0) {
        err = s_close_notify(client);
        if (err != AH_ENONE) {
            return err;
        }
        // s_close_notify() calls ah_i_mbedtls_ssl_on_send(), which adds a new entry of unset kind to the send queue.
        struct ah_i_mbedtls_send_queue_entry* entry = ah_i_ring_peek(&client->_send_ciphertext_queue);
        if (entry == NULL || entry->kind != S_SEND_QUEUE_ENTRY_KIND_NORMAL) {
            return AH_EINTERN;
        }
        entry->kind = S_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR;
    }

    if (ah_tcp_conn_is_readable(conn) && (flags & AH_TCP_SHUTDOWN_RD) != 0) {
        err = client->_trans.vtab->conn_shutdown(client->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
        if (err != AH_ENONE) {
            return err;
        }
    }

    return AH_ENONE;
}

static ah_err_t s_close_notify(ah_mbedtls_client_t* client)
{
    ah_assert_if_debug(client != NULL);

    int res = mbedtls_ssl_close_notify(&client->_ssl);

    if (res < 0) {
        return ah_i_mbedtls_res_to_err(&client->_errs, res);
    }

    return AH_ENONE;
}

ah_err_t ah_i_mbedtls_client_close(void* client_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_close == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (ah_tcp_conn_is_writable(conn)) {
        ah_err_t err = s_close_notify(client);

        if (err == AH_ENONE) {
            // s_close_notify() calls ah_i_mbedtls_ssl_on_send(), which adds a new entry of unset kind to the send queue.
            struct ah_i_mbedtls_send_queue_entry* entry = ah_i_ring_peek(&client->_send_ciphertext_queue);
            if (entry == NULL || entry->kind != S_SEND_QUEUE_ENTRY_KIND_NORMAL) {
                return AH_EINTERN;
            }
            entry->kind = S_SEND_QUEUE_ENTRY_KIND_CLOSE;
        }

        return err;
    }

    return client->_trans.vtab->conn_close(client->_trans.ctx, conn);
}

static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_close(conn, AH_ESTATE);
        return;
    }

    ah_mbedtls_client_term(client);

    client->_conn_cbs->on_close(conn, err);
}

void ah_i_mbedtls_handshake(ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);

    if (client == NULL) {
        conn->_cbs->on_write(conn, AH_ESTATE);
        return;
    }

    int res;
    ah_err_t err;

    res = mbedtls_ssl_handshake(&client->_ssl);

    switch (res) {
    case 0:
        client->_is_handshake_done = true;

        if (client->_is_stopping_reads_on_handshake_completion) {
            client->_is_stopping_reads_on_handshake_completion = false;
            err = ah_tcp_conn_read_stop(conn);
            if (err != AH_ENONE) {
                err = AH_EINTERN;
                break;
            }
        }

        const mbedtls_x509_crt* peer_cert;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        peer_cert = mbedtls_ssl_get_peer_cert(&client->_ssl);
#else
        peer_cert = NULL;
#endif
        client->_on_handshake_done_cb(conn, peer_cert, AH_ENONE);

        return;

    case MBEDTLS_ERR_SSL_WANT_READ:
        client->_is_handshaking_on_next_read_data = true;
        if (ah_tcp_conn_is_reading(conn)) {
            return;
        }
        err = client->_trans.vtab->conn_read_start(client->_trans.ctx, conn);
        if (err != AH_ENONE) {
            break;
        }
        return;

    case MBEDTLS_ERR_SSL_WANT_WRITE:
        // As of MbedTLS versions 2.28.0 and 3.1.0, this result code is only
        // possible if either of the send or receive callbacks set via
        // mbedtls_ssl_set_bio() return it. None of our callbacks (s_ssl_recv()
        // and ah_i_mbedtls_ssl_on_send()) do. We, therefore, hope that this behavior will
        // remain consistent across future versions and treat the occurrence of
        // this result code as an internal error.
        err = AH_EINTERN;
        break;

    case MBEDTLS_ERR_ERROR_GENERIC_ERROR:
        if (client->_errs._pending_ah_err != AH_ENONE) {
            err = client->_errs._pending_ah_err;
            client->_errs._pending_ah_err = AH_ENONE;
            break;
        }
        // fallthrough

    default:
        client->_errs._last_mbedtls_err = res;
        err = AH_EDEP;
        break;
    }

    client->_on_handshake_done_cb(conn, NULL, err);
}

// Called to send handshake data or encrypted payload data.
int ah_i_mbedtls_ssl_on_send(void* conn_, const unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_tcp_conn_t* conn = conn_;

    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);
    if (client == NULL) {
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

    struct ah_i_mbedtls_send_queue_entry* entry = ah_i_ring_alloc(&client->_send_ciphertext_queue);
    if (entry == NULL) {
        err = AH_ENOMEM;
        goto handle_err;
    }

    entry->kind = S_SEND_QUEUE_ENTRY_KIND_NORMAL;

    err = ah_buf_init(&entry->out.buf, (uint8_t*) buf, len);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    if (client->_trans.vtab == NULL || client->_trans.vtab->conn_write == NULL) {
        err = AH_ESTATE;
        goto handle_err;
    }
    err = client->_trans.vtab->conn_write(client->_trans.ctx, conn, &entry->out);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return (int) len;

handle_err:
    client->_errs._pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

// Called to get handshake data or encrypted payload data, if available.
int ah_i_mbedtls_ssl_on_recv(void* conn_, unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_tcp_conn_t* conn = conn_;

    ah_mbedtls_client_t* client = ah_mbedtls_conn_get_client(conn);
    if (client == NULL) {
        err = AH_ESTATE;
        goto handle_err;
    }

    if (conn == NULL || (buf == NULL && len != 0u)) {
        err = AH_ESTATE;
        goto handle_err;
    }

    size_t n_available_bytes = ah_buf_get_size(&client->_recv_ciphertext_buf);
    if (n_available_bytes == 0u) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (len > n_available_bytes) {
        len = n_available_bytes;
    }
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    memcpy(buf, ah_buf_get_base(&client->_recv_ciphertext_buf), len);

    ah_buf_skipn(&client->_recv_ciphertext_buf, len);

    return (int) len;

handle_err:
    client->_errs._pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}
