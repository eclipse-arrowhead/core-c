// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>

// Response states.
#define S_RES_STATE_INIT       0x01
#define S_RES_STATE_STAT_LINE  0x02
#define S_RES_STATE_HEADERS    0x04
#define S_RES_STATE_DATA       0x08
#define S_RES_STATE_CHUNK_LINE 0x10
#define S_RES_STATE_CHUNK_DATA 0x20
#define S_RES_STATE_TRAILER    0x40

// Output (request) states.
#define S_O_STATE_READY        0u
#define S_O_STATE_SENDING_HEAD 1u
#define S_O_STATE_SENDING_BODY 2u

#define S_RES_STATE_IS_REUSING_BUF_RW(STATE) \
 (((STATE) & (S_RES_STATE_STAT_LINE | S_RES_STATE_HEADERS | S_RES_STATE_CHUNK_LINE | S_RES_STATE_TRAILER)) != 0u)

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);

static bool s_req_queue_is_empty(struct ah_i_http_req_queue* queue);
static bool s_req_queue_is_empty_then_add(struct ah_i_http_req_queue* queue, ah_http_req_t* req);
static ah_http_req_t* s_req_queue_peek(struct ah_i_http_req_queue* queue);
static void s_req_queue_remove_unsafe(struct ah_i_http_req_queue* queue);

ah_err_t s_prep_write_req(ah_http_client_t* cln);
ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab)
{
    if (cln == NULL || trans._vtab == NULL || trans._loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    ah_assert_if_debug(trans._vtab->conn_init != NULL);
    ah_assert_if_debug(trans._vtab->conn_open != NULL);
    ah_assert_if_debug(trans._vtab->conn_connect != NULL);
    ah_assert_if_debug(trans._vtab->conn_read_start != NULL);
    ah_assert_if_debug(trans._vtab->conn_read_stop != NULL);
    ah_assert_if_debug(trans._vtab->conn_write != NULL);
    ah_assert_if_debug(trans._vtab->conn_shutdown != NULL);
    ah_assert_if_debug(trans._vtab->conn_close != NULL);

    ah_assert_if_debug(vtab->on_open != NULL);
    ah_assert_if_debug(vtab->on_connect != NULL);
    ah_assert_if_debug(vtab->on_close != NULL);
    ah_assert_if_debug(vtab->on_req_sent != NULL);
    ah_assert_if_debug(vtab->on_res_alloc != NULL);
    ah_assert_if_debug(vtab->on_res_stat_line != NULL);
    ah_assert_if_debug(vtab->on_res_header != NULL);
    ah_assert_if_debug(vtab->on_res_data != NULL);
    ah_assert_if_debug(vtab->on_res_end != NULL);

    static const ah_tcp_conn_vtab_t s_vtab = {
        .on_open = s_on_open,
        .on_connect = s_on_connect,
        .on_close = s_on_close,
        .on_read_alloc = s_on_read_alloc,
        .on_read_data = s_on_read_data,
        .on_read_err = s_on_read_err,
        .on_write_done = s_on_write_done,
    };

    ah_err_t err = trans._vtab->conn_init(&cln->_conn, trans._loop, &s_vtab);
    if (err != AH_ENONE) {
        return err;
    }

    cln->_conn._trans_data = trans._data;
    cln->_trans_vtab = trans._vtab;
    cln->_vtab = vtab;

    cln->_res_state = S_RES_STATE_INIT;
    cln->_res_state = S_O_STATE_READY;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_open(&cln->_conn, laddr);
}

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_open(cln, err);
}

ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    ah_err_t err = cln->_trans_vtab->conn_connect(&cln->_conn, raddr);
    if (err == AH_ENONE) {
        cln->_raddr = raddr;
    }
    return err;
}

static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_connect(cln, err);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    ah_err_t err;

    if (S_RES_STATE_IS_REUSING_BUF_RW(cln->_res_state)) {
        ah_buf_rw_get_writable_as_buf(&cln->_res_buf_rw, buf);
        return;
    }

    ah_http_req_t* req = s_req_queue_peek(&cln->_req_queue);
    if (req == NULL) {
        err = AH_ESTATE;
        goto close_conn_and_report_err;
    }

    cln->_vtab->on_res_alloc(cln, req, buf);
    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
        return;
    }
    if (ah_buf_get_size(buf) == 0u) {
        err = AH_ENOBUFS;
        goto close_conn_and_report_err;
    }

    ah_buf_rw_init_for_writing_to(&cln->_res_buf_rw, buf);

    return;

close_conn_and_report_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_end(cln, NULL, err);
}

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn)
{
    ah_assert_if_debug(conn != NULL);

    // This is only safe if `conn` is a member of an ah_http_client_t value.
    const size_t conn_member_offset = offsetof(ah_http_client_t, _conn);
    ah_assert_if_debug(conn_member_offset <= PTRDIFF_MAX);
    ah_http_client_t* cln = (ah_http_client_t*) &((uint8_t*) conn)[-((ptrdiff_t) conn_member_offset)];

    ah_assert_if_debug(cln->_vtab != NULL);
    ah_assert_if_debug(cln->_trans_vtab != NULL);

    return cln;
}

static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    ah_err_t err;

    ah_assert_if_debug(cln->_res_buf_rw.wr == ah_buf_get_base_const(buf));
    (void) buf;

    if (!ah_buf_rw_juken(&cln->_res_buf_rw, nread)) {
        err = AH_EDOM;
        goto close_conn_and_report_err;
    }

    switch (cln->_res_state) {
    case S_RES_STATE_INIT: {
        if (s_req_queue_is_empty(&cln->_req_queue)) {
            err = AH_ESTATE;
            goto close_conn_and_report_err;
        }

        ah_http_req_t* req = s_req_queue_peek(&cln->_req_queue);
        cln->_keep_alive = req->req_line.version.minor != 0u;

        cln->_res_state = S_RES_STATE_STAT_LINE;
        goto state_stat_line;
    }

    state_stat_line:
    case S_RES_STATE_STAT_LINE: {
        ah_http_stat_line_t stat_line;
        err = ah_i_http_parse_stat_line(&cln->_res_buf_rw, &stat_line);
        if (err != AH_ENONE) {
            break;
        }

        cln->_vtab->on_res_stat_line(cln, s_req_queue_peek(&cln->_req_queue), &stat_line);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_res_state = S_RES_STATE_HEADERS;
        goto state_headers;
    }

    state_headers:
    case S_RES_STATE_HEADERS: {
        bool has_connection_close_been_seen = false;
        bool has_content_length_been_seen = false;
        bool has_transfer_encoding_chunked_been_seen = false;
        size_t content_length;

        ah_http_req_t* req = s_req_queue_peek(&cln->_req_queue);

        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_res_buf_rw, &header);
            if (err != AH_ENONE) {
                break;
            }

            if (header.name == NULL) {
                if (cln->_vtab->on_res_headers != NULL) {
                    cln->_vtab->on_res_headers(cln, req);
                    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                        return;
                    }
                }

                if (has_transfer_encoding_chunked_been_seen) {
                    if (content_length != 0u) {
                        err = AH_EBADMSG;
                        goto close_conn_and_report_err;
                    }
                    cln->_res_state = S_RES_STATE_CHUNK_LINE;
                    goto state_chunk_line;
                }

                if (!has_content_length_been_seen || content_length == 0u) {
                    goto state_end;
                }

                cln->_res_n_expected_bytes = content_length;
                cln->_res_state = S_RES_STATE_DATA;
                goto state_data;
            }

            if (ah_i_http_header_name_eq("content-length", header.name)) {
                if (has_content_length_been_seen) {
                    err = AH_EDUP;
                    goto close_conn_and_report_err;
                }
                err = ah_i_http_header_value_to_size(header.value, &content_length);
                if (err != AH_ENONE) {
                    goto close_conn_and_report_err;
                }
                has_content_length_been_seen = true;
            }
            else if (ah_i_http_header_name_eq("transfer-encoding", header.name)) {
                const char* rest;
                err = ah_i_http_header_value_has_csv(header.value, "chunked", &rest);
                switch (err) {
                case AH_ENONE:
                    // The `chunked` transfer-encoding must be last if used.
                    // See https://www.rfc-editor.org/rfc/rfc7230#section-3.3.3.
                    if (rest[0u] != '\0') {
                        err = AH_EBADMSG;
                        goto close_conn_and_report_err;
                    }

                    if (has_transfer_encoding_chunked_been_seen) {
                        err = AH_EDUP;
                        goto close_conn_and_report_err;
                    }
                    has_transfer_encoding_chunked_been_seen = true;
                    break;

                case AH_ESRCH:
                    break;

                default:
                    goto close_conn_and_report_err;
                }
            }
            else if (ah_i_http_header_name_eq("connection", header.name)) {
                // The "connection" header itself and its defined values is
                // permitted to occur more than once. See
                // https://datatracker.ietf.org/doc/html/rfc7230#section-6.3.
                if (ah_i_http_header_value_has_csv(header.value, "close", NULL)) {
                    cln->_keep_alive = false;
                    has_connection_close_been_seen = true;
                }
                else if (req->req_line.version.minor == 0u && !has_connection_close_been_seen) {
                    if (ah_i_http_header_value_has_csv(header.value, "keep-alive", NULL)) {
                        cln->_keep_alive = true;
                    }
                }
            }

            cln->_vtab->on_res_header(cln, req, header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_chunk_line:
    case S_RES_STATE_CHUNK_LINE: {
        ah_http_chunk_line_t chunk_line;

        err = ah_i_http_parse_chunk_line(&cln->_res_buf_rw, &chunk_line);
        if (err != AH_ENONE) {
            break;
        }

        if (cln->_vtab->on_res_chunk_line != NULL) {
            cln->_vtab->on_res_chunk_line(cln, s_req_queue_peek(&cln->_req_queue), chunk_line);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }

        if (chunk_line.size == 0u) {
            ah_assert_if_debug(cln->_res_n_expected_bytes == 0u);
            cln->_res_state = S_RES_STATE_TRAILER;
            goto state_trailer;
        }

        cln->_res_n_expected_bytes = chunk_line.size;
        cln->_res_state = S_RES_STATE_CHUNK_DATA;
        goto state_chunk_data;
    }

    state_data:
    state_chunk_data:
    case S_RES_STATE_DATA:
    case S_RES_STATE_CHUNK_DATA: {
        ah_buf_t readable_buf;
        ah_buf_rw_get_readable_as_buf(&cln->_res_buf_rw, &readable_buf);

        ah_buf_limit_size_to(&readable_buf, cln->_res_n_expected_bytes);
        cln->_res_n_expected_bytes -= ah_buf_get_size(&readable_buf);

        cln->_vtab->on_res_data(cln, s_req_queue_peek(&cln->_req_queue), &readable_buf);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        if (cln->_res_n_expected_bytes == 0u) {
            if (cln->_res_state == S_RES_STATE_DATA) {
                goto state_end;
            }
            cln->_res_state = S_RES_STATE_CHUNK_LINE;
            goto state_chunk_line;
        }

        return;
    }

    state_trailer:
    case S_RES_STATE_TRAILER: {
        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_res_buf_rw, &header);
            if (err != AH_ENONE) {
                break;
            }

            if (header.name == NULL) {
                goto state_end;
            }

            cln->_vtab->on_res_header(cln, s_req_queue_peek(&cln->_req_queue), header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_end : {
        cln->_vtab->on_res_end(cln, s_req_queue_peek(&cln->_req_queue), AH_ENONE);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        s_req_queue_remove_unsafe(&cln->_req_queue);

        if (!cln->_keep_alive) {
            err = cln->_trans_vtab->conn_close(conn);
            if (err != AH_ENONE) {
                goto report_err;
            }
        }

        if (s_req_queue_is_empty(&cln->_req_queue)) {
            if (ah_buf_rw_get_readable_size(&cln->_res_buf_rw) != 0u) {
                err = AH_ESTATE;
                goto close_conn_and_report_err;
            }
            cln->_res_state = S_RES_STATE_INIT;
            return;
        }

        cln->_res_state = S_RES_STATE_STAT_LINE;
        goto state_stat_line;
    }

    default:
        ah_unreachable();
    }

close_conn_and_report_err:
    if (!ah_tcp_conn_is_closed(conn)) {
        (void) cln->_trans_vtab->conn_close(conn);
    }
report_err:
    cln->_vtab->on_res_end(cln, s_req_queue_peek(&cln->_req_queue), err);
}

static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_res_end(cln, s_req_queue_peek(&cln->_req_queue), err);
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, ah_http_req_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }
    if (req->req_line.version.major != 1u) {
        return AH_EPROTONOSUPPORT;
    }

    if (s_req_queue_is_empty_then_add(&cln->_req_queue, req)) {
        return s_prep_write_req(cln);
    }

    return AH_ENONE;
}

ah_err_t s_prep_write_req(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    return AH_EOPNOTSUPP; // TODO: Implement.
}

static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    // TODO: Check state, report if sending is complete or failed.
    (void) cln;
    (void) err;
}

ah_extern ah_err_t ah_http_client_send_chunk(ah_http_client_t* cln, ah_http_chunk_line_t chunk, ah_bufs_t bufs)
{
    (void) cln;
    (void) chunk;
    (void) bufs;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_client_send_data(ah_http_client_t* cln, ah_bufs_t bufs)
{
    (void) cln;
    (void) bufs;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_client_send_trailer(ah_http_client_t* cln, ah_http_header_t* headers)
{
    (void) cln;
    (void) headers;
    return AH_EOPNOTSUPP; // TODO: Implement.
}

ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_close(&cln->_conn);
}

static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_close(cln, err);

    for (ah_http_req_t* req;;) {
        req = s_req_queue_peek(&cln->_req_queue);
        if (req == NULL) {
            break;
        }
        ah_err_t err0 = cln->_trans_vtab->conn_connect(&cln->_conn, cln->_raddr);
        if (err0 == AH_ENONE) {
            break;
        }
        s_req_queue_remove_unsafe(&cln->_req_queue);
        cln->_vtab->on_req_sent(cln, req, err0);
    }
}

ah_extern ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    return &cln->_conn;
}

ah_extern void* ah_http_client_get_user_data(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    return ah_tcp_conn_get_user_data(&cln->_conn);
}

ah_extern void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data)
{
    ah_assert_if_debug(cln != NULL);

    ah_tcp_conn_set_user_data(&cln->_conn, user_data);
}

static bool s_req_queue_is_empty(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    return queue->_head == NULL;
}

static bool s_req_queue_is_empty_then_add(struct ah_i_http_req_queue* queue, ah_http_req_t* req)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(req != NULL);

    req->_next = NULL;

    if (queue->_head == NULL) {
        queue->_head = req;
        queue->_end = req;
        return true;
    }

    queue->_end->_next = req;
    queue->_end = req;

    return false;
}

static ah_http_req_t* s_req_queue_peek(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);

    return queue->_head;
}

static void s_req_queue_remove_unsafe(struct ah_i_http_req_queue* queue)
{
    ah_assert_if_debug(queue != NULL);
    ah_assert_if_debug(queue->_head != NULL);
    ah_assert_if_debug(queue->_end != NULL);

    ah_http_req_t* req = queue->_head;
    queue->_head = req->_next;

#ifndef NDEBUG

    req->_next = NULL;

    if (queue->_head == NULL) {
        queue->_end = NULL;
    }

#endif
}
