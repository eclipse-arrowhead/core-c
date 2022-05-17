// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>

// Request states.
#define S_REQ_STATE_INIT       0x01
#define S_REQ_STATE_LINE       0x02
#define S_REQ_STATE_HEADERS    0x04
#define S_REQ_STATE_DATA       0x08
#define S_REQ_STATE_CHUNK_LINE 0x10
#define S_REQ_STATE_CHUNK_DATA 0x20
#define S_REQ_STATE_TRAILER    0x40

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread, ah_err_t err);
static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err);

void ah_i_http_rclient_init(ah_http_rclient_t* cln, ah_http_server_t* srv, const ah_sockaddr_t* raddr)
{
    ah_assert_if_debug(cln != NULL);
    ah_assert_if_debug(!ah_tcp_conn_is_closed(&cln->_conn));
    ah_assert_if_debug(srv != NULL);
    ah_assert_if_debug(raddr != NULL);

    cln->_raddr = raddr;
    cln->_trans_vtab = srv->_trans_vtab;
    cln->_vtab = srv->_rclient_vtab;
    cln->_res_queue = (struct ah_i_http_res_queue) { 0u };
    cln->_srv = srv;
    cln->_req_state = S_REQ_STATE_INIT;
}

const ah_tcp_conn_vtab_t* ah_i_http_rclient_get_conn_vtab()
{
    static const ah_tcp_conn_vtab_t s_vtab = {
        .on_close = s_on_conn_close,
        .on_read_alloc = s_on_conn_read_alloc,
        .on_read_data = s_on_conn_read_data,
        .on_write_done = s_on_conn_write_done,
    };
    return &s_vtab;
}

static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) buf; // TODO: Implement.
}

static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) buf; // TODO: Implement.
    (void) nread;
    (void) err;
}

static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) err; // TODO: Implement.
}

ah_extern ah_err_t ah_http_rclient_send_data(ah_http_rclient_t* cln, ah_tcp_msg_t* msg)
{
    if (cln == NULL || msg == NULL) {
        return AH_EINVAL;
    }
/*
    ah_http_res_t* res = s_res_queue_peek(&cln->_req_queue);
    if (res == NULL) {
        return AH_ESTATE;
    }

    if (res->body._as_any._kind != AH_I_HTTP_BODY_KIND_OVERRIDE) {
        return AH_ESTATE;
    }

    ah_err_t err = cln->_trans_vtab->conn_write(&cln->_conn, msg);
    if (err != AH_ENONE) {
        return err;
    }

    res->_n_pending_tcp_msgs += 1u;
*/
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_rclient_send_end(ah_http_rclient_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    /*
    ah_http_res_t* res = s_res_queue_peek_unsafe(&cln->_req_queue);

    if (res->body._as_any._kind != AH_I_HTTP_BODY_KIND_OVERRIDE) {
        return AH_ESTATE;
    }

    res->body._as_any._kind = AH_I_HTTP_BODY_KIND_EMPTY;

    if (res->_n_pending_tcp_msgs > 0u) {
        return AH_ENONE;
    }

    s_complete_current_res(cln, AH_ENONE);
*/
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_rclient_send_chunk(ah_http_rclient_t* cln, ah_http_chunk_t* chunk)
{
    if (cln == NULL || chunk == NULL) {
        return AH_EINVAL;
    }
#ifndef NDEBUG
    if (chunk->ext != NULL && chunk->ext[0u] != '\0' && chunk->ext[0u] != ';') {
        return AH_EILSEQ;
    }
#endif

    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_rclient_send_trailer(ah_http_rclient_t* cln, ah_http_trailer_t* trailer)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
#ifndef NDEBUG
    if (trailer->ext != NULL && trailer->ext[0u] != '\0' && trailer->ext[0u] != ';') {
        return AH_EILSEQ;
    }
#endif

    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_rclient_close(ah_http_rclient_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_close(&cln->_conn);
}

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_assert_if_debug(conn != NULL);
    (void) conn;
    (void) err; // TODO: Implement.
}

ah_extern ah_tcp_conn_t* ah_http_rclient_get_conn(ah_http_rclient_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    return &cln->_conn;
}

ah_extern ah_http_server_t* ah_http_rclient_get_server(ah_http_rclient_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    return cln->_srv;
}

ah_extern void* ah_http_rclient_get_user_data(ah_http_rclient_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    return ah_tcp_conn_get_user_data(&cln->_conn);
}

ah_extern void ah_http_rclient_set_user_data(ah_http_rclient_t* cln, void* user_data)
{
    ah_assert_if_debug(cln != NULL);

    ah_tcp_conn_set_user_data(&cln->_conn, user_data);
}
