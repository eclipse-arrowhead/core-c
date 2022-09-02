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

static void s_on_open(void* client_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(void* client_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read(void* client_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_on_write(void* client_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_on_close(void* client_, ah_tcp_conn_t* conn, ah_err_t err);

static ah_err_t s_close_notify(ah_mbedtls_client_t* client, uint8_t kind);

const ah_tcp_conn_cbs_t ah_i_mbedtls_tcp_conn_cbs = {
    .on_open = s_on_open,
    .on_connect = s_on_connect,
    .on_read = s_on_read,
    .on_write = s_on_write,
    .on_close = s_on_close,
};

ah_extern ah_err_t ah_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    if (client == NULL || !ah_tcp_trans_vtab_is_valid(trans.vtab) || ssl_conf == NULL || on_handshake_done_cb == NULL) {
        return AH_EINVAL;
    }

    return ah_i_mbedtls_client_init(client, trans, ssl_conf, on_handshake_done_cb);
}

ah_extern int ah_mbedtls_client_get_last_err(ah_mbedtls_client_t* client)
{
    if (client == NULL) {
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
    return client->_errs._last_mbedtls_err;
}

ah_extern mbedtls_ssl_context* ah_mbedtls_client_get_ssl_context(ah_mbedtls_client_t* client)
{
    if (client == NULL) {
        return NULL;
    }
    return &client->_ssl;
}

ah_extern ah_tcp_trans_t ah_mbedtls_client_as_trans(ah_mbedtls_client_t* client)
{
    return (ah_tcp_trans_t) {
        .vtab = &ah_i_mbedtls_tcp_vtab,
        .ctx = client,
    };
}

ah_extern ah_tcp_conn_t* ah_mbedtls_client_get_conn(ah_mbedtls_client_t* client)
{
    if (client == NULL) {
        return NULL;
    }
    return client->_conn;
}

ah_extern void ah_mbedtls_client_term(ah_mbedtls_client_t* client)
{
    if (client == NULL) {
        return;
    }

    mbedtls_ssl_free(&client->_ssl);
    ah_i_ring_term(&client->_out_queue_ciphertext);

    if (client->_server != NULL) {
        ah_i_tls_server_free_accepted_client(client->_server, client);
    }
}

ah_err_t ah_i_mbedtls_client_init(ah_mbedtls_client_t* client, ah_tcp_trans_t trans, mbedtls_ssl_config* ssl_conf, ah_mbedtls_on_handshake_done_cb on_handshake_done_cb)
{
    ah_assert_if_debug(client != NULL);
    ah_assert_if_debug(ah_tcp_trans_vtab_is_valid(trans.vtab));
    ah_assert_if_debug(ssl_conf != NULL);
    ah_assert_if_debug(on_handshake_done_cb != NULL);

    int res;

    *client = (ah_mbedtls_client_t) {
        ._trans = trans,
        ._on_handshake_done_cb = on_handshake_done_cb,
    };

    ah_err_t err = ah_i_ring_init(&client->_out_queue_ciphertext, 4u, sizeof(struct s_send_queue_entry));
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

ah_err_t ah_i_mbedtls_conn_init(void* ctx, ah_tcp_conn_t* conn, ah_loop_t* loop, ah_tcp_trans_t trans, ah_tcp_conn_obs_t obs)
{
    if (ctx == NULL || conn == NULL || !ah_tcp_conn_cbs_is_valid_for_connection(obs.cbs)) {
        return AH_EINVAL;
    }

    ah_mbedtls_client_t* client = ctx;

    client->_conn = conn;
    client->_conn_obs = obs;

    ah_assert_if_debug(client->_trans.vtab != NULL && client->_trans.vtab->conn_init != NULL);

    return client->_trans.vtab->conn_init(client->_trans.ctx, conn, loop, trans, (ah_tcp_conn_obs_t) { &ah_i_mbedtls_tcp_conn_cbs, client });
}

ah_err_t ah_i_mbedtls_conn_open(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* laddr)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL) {
        return AH_EINVAL;
    }

    mbedtls_ssl_set_bio(&client->_ssl, client, ah_i_mbedtls_client_write_ciphertext, ah_i_mbedtls_client_read_ciphertext, NULL);

    ah_assert_if_debug(client->_trans.vtab != NULL && client->_trans.vtab->conn_open != NULL);

    return client->_trans.vtab->conn_open(client->_trans.ctx, conn, laddr);
}

static void s_on_open(void* client_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = client_;
    ah_assert_if_debug(client != NULL);

    client->_conn_obs.cbs->on_open(client->_conn_obs.ctx, conn, err);
}

ah_err_t ah_i_mbedtls_conn_connect(void* client_, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr)
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

static void s_on_connect(void* client_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = client_;
    ah_assert_if_debug(client != NULL);

    client->_is_handshake_done = false;
    client->_conn_obs.cbs->on_connect(client->_conn_obs.ctx, conn, err);
}

ah_err_t ah_i_mbedtls_conn_read_start(void* client_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_read_start == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    err = ah_tcp_in_alloc_for(&client->_in_plaintext);
    if (err != AH_ENONE) {
        return err;
    }

    err = client->_trans.vtab->conn_read_start(client->_trans.ctx, conn);
    if (err != AH_ENONE) {
        ah_tcp_in_free(client->_in_plaintext);
        return err;
    }

    ah_i_mbedtls_handshake(client);

    return AH_ENONE;
}

static void s_on_read(void* client_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    ah_mbedtls_client_t* client = client_;
    ah_assert_if_debug(client != NULL);

    if (err != AH_ENONE) {
        goto handle_err;
    }

    client->_in_ciphertext = in;

handshake_again:
    if (!client->_is_handshake_done) {
        ah_i_mbedtls_handshake(client);

        if (!client->_is_handshake_done) {
            return;
        }
    }

    while (ah_rw_is_readable(&client->_in_ciphertext->rw)) {
        void* buf = client->_in_plaintext->rw.w;
        size_t len = ah_rw_get_writable_size(&client->_in_plaintext->rw);

        // This call will make MbedTLS pull the ciphertext in
        // `client->_in_ciphertext` through the appropriate decryption
        // algorithms and write the result to `client->_in_plaintext`. See also
        // `ah_i_mbedtls_client_read_ciphertext()`.
        int res = mbedtls_ssl_read(&client->_ssl, buf, len);

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
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                client->_is_handshake_done = false;
                goto handshake_again;

            default:
                client->_errs._last_mbedtls_err = res;
                err = AH_EDEP;
                goto handle_err;
            }
        }

        if (!ah_rw_juken(&client->_in_plaintext->rw, (size_t) res)) {
            err = AH_EINTERN;
            goto handle_err;
        }

        client->_conn_obs.cbs->on_read(client->_conn_obs.ctx, conn, client->_in_plaintext, AH_ENONE);
    }

    return;

handle_err:
    client->_conn_obs.cbs->on_read(client->_conn_obs.ctx, conn, NULL, err);
}

ah_err_t ah_i_mbedtls_conn_read_stop(void* client_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_read_stop == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = client->_trans.vtab->conn_read_stop(client->_trans.ctx, conn);
    if (err != AH_ENONE) {
        return err;
    }

    ah_tcp_in_free(client->_in_plaintext);

    return AH_ENONE;
}

ah_err_t ah_i_mbedtls_conn_write(void* client_, ah_tcp_conn_t* conn, ah_tcp_out_t* out)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    struct s_send_queue_entry* entry = ah_i_ring_alloc(&client->_out_queue_ciphertext);
    if (entry == NULL) {
        return AH_ENOMEM;
    }
    entry->_kind = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_NORMAL;
    entry->_state = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_PENDING;

    int res = mbedtls_ssl_write(&client->_ssl, out->buf.base, out->buf.size);
    if (res < 0) {
        switch (res) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            return AH_ERECONN;

        case MBEDTLS_ERR_SSL_WANT_WRITE:
            return AH_ENONE;

        default:
            return ah_i_mbedtls_res_to_err(&client->_errs, res);
        }
    }

    // We guarantee that all data in out is written every time.
    if (out->buf.size != (size_t) res) {
        return AH_EINTERN;
    }

    return AH_ENONE;
}

static void s_on_write(void* client_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    ah_mbedtls_client_t* client = client_;
    ah_assert_if_debug(client != NULL);

    struct s_send_queue_entry* entry = ah_i_ring_peek(&client->_out_queue_ciphertext);
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
    else if (entry->_kind == AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_CLOSE) {
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
        ah_i_mbedtls_handshake(client);
        return;
    }

handle_err:
    client->_conn_obs.cbs->on_write(client->_conn_obs.ctx, conn, out, err);
}

ah_err_t ah_i_mbedtls_conn_shutdown(void* client_, ah_tcp_conn_t* conn, uint8_t flags)
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
        err = s_close_notify(client, AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_SHUTDOWN_WR);
        if (err != AH_ENONE) {
            return err;
        }
    }

    if (ah_tcp_conn_is_readable(conn) && (flags & AH_TCP_SHUTDOWN_RD) != 0) {
        err = client->_trans.vtab->conn_shutdown(client->_trans.ctx, conn, AH_TCP_SHUTDOWN_RD);
        if (err != AH_ENONE) {
            return err;
        }
    }

    return AH_ENONE;
}

static ah_err_t s_close_notify(ah_mbedtls_client_t* client, uint8_t kind)
{
    ah_assert_if_debug(client != NULL);

    struct s_send_queue_entry* entry = ah_i_ring_alloc(&client->_out_queue_ciphertext);
    if (entry == NULL) {
        return AH_ENOMEM;
    }
    entry->_kind = kind;
    entry->_state = AH_S_MBEDTLS_SEND_QUEUE_ENTRY_STATE_PENDING;

    int res = mbedtls_ssl_close_notify(&client->_ssl);

    if (res < 0) {
        if (res == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return AH_ENONE;
        }
        return ah_i_mbedtls_res_to_err(&client->_errs, res);
    }

    return AH_ENONE;
}

ah_err_t ah_i_mbedtls_conn_close(void* client_, ah_tcp_conn_t* conn)
{
    ah_mbedtls_client_t* client = client_;
    if (client == NULL || client->_trans.vtab == NULL || client->_trans.vtab->conn_close == NULL) {
        return AH_ESTATE;
    }
    if (conn == NULL) {
        return AH_EINVAL;
    }

    if (ah_tcp_conn_is_writable(conn)) {
        return s_close_notify(client, AH_S_MBEDTLS_SEND_QUEUE_ENTRY_KIND_CLOSE);
    }

    return client->_trans.vtab->conn_close(client->_trans.ctx, conn);
}

static void s_on_close(void* client_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_mbedtls_client_t* client = client_;
    ah_assert_if_debug(client != NULL);

    client->_conn_obs.cbs->on_close(client->_conn_obs.ctx, conn, err);

    ah_tcp_in_free(client->_in_plaintext);

    if (client->_server != NULL) {
        ah_mbedtls_client_term(client);
    }
}

void ah_i_mbedtls_handshake(ah_mbedtls_client_t* client)
{
    ah_assert_if_debug(client != NULL);

    int res;
    ah_err_t err;

    res = mbedtls_ssl_handshake(&client->_ssl);

    switch (res) {
    case 0:
        client->_is_handshake_done = true;

        const mbedtls_x509_crt* peer_cert;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        peer_cert = mbedtls_ssl_get_peer_cert(&client->_ssl);
#else
        peer_cert = NULL;
#endif
        client->_on_handshake_done_cb(client, peer_cert, AH_ENONE);

        return;

    case MBEDTLS_ERR_SSL_WANT_READ:
    case MBEDTLS_ERR_SSL_WANT_WRITE:
        return;

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

    client->_on_handshake_done_cb(client, NULL, err);
}

// Called to send handshake data or encrypted payload data.
int ah_i_mbedtls_client_write_ciphertext(void* client_, const unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_mbedtls_client_t* client = client_;
    if (client == NULL) {
        err = AH_EINTERN;
        goto handle_err;
    }

    ah_tcp_conn_t* conn = client->_conn;
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

    struct s_send_queue_entry* entry = ah_i_ring_peek(&client->_out_queue_ciphertext);
    if (entry == NULL) {
        if (client->_is_handshake_done) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        entry = ah_i_ring_alloc(&client->_out_queue_ciphertext);
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
        ah_i_ring_skip(&client->_out_queue_ciphertext);
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

    if (client->_trans.vtab == NULL || client->_trans.vtab->conn_write == NULL) {
        err = AH_EINTERN;
        goto handle_err;
    }
    err = client->_trans.vtab->conn_write(client->_trans.ctx, conn, &entry->_out);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return MBEDTLS_ERR_SSL_WANT_WRITE;

handle_err:
    ah_i_ring_skip(&client->_out_queue_ciphertext);
    client->_errs._pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}

// Called to get handshake data or encrypted payload data, if available.
int ah_i_mbedtls_client_read_ciphertext(void* client_, unsigned char* buf, size_t len)
{
    ah_err_t err;

    ah_mbedtls_client_t* client = client_;
    if (client == NULL) {
        err = AH_EINTERN;
        goto handle_err;
    }

    if (buf == NULL && len != 0u) {
        err = AH_EINTERN;
        goto handle_err;
    }

    if (client->_in_ciphertext == NULL) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    size_t n_available_bytes = ah_rw_get_readable_size(&client->_in_ciphertext->rw);
    if (n_available_bytes == 0u) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (len > n_available_bytes) {
        len = n_available_bytes;
    }
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    if (!ah_rw_readn(&client->_in_ciphertext->rw, buf, len)) {
        err = AH_EINTERN;
        goto handle_err;
    }

    return (int) len;

handle_err:
    client->_errs._pending_ah_err = err;
    return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
}
