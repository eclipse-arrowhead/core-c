// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"
#include "http-utils.h"

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

#define S_REQ_STATE_IS_REUSING_BUF_RW(STATE) \
 (((STATE) & (S_REQ_STATE_LINE | S_REQ_STATE_HEADERS | S_REQ_STATE_CHUNK_LINE | S_REQ_STATE_TRAILER)) != 0u)

static void s_on_conn_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread, ah_err_t err);
static void s_on_conn_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static ah_err_t s_realloc_res_rw(ah_http_rclient_t* cln);

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
    ah_http_rclient_t* cln = ah_i_http_upcast_to_rclient(conn);

    ah_err_t err;
    uint16_t code;

    if (S_REQ_STATE_IS_REUSING_BUF_RW(cln->_req_state)) {
        ah_buf_rw_get_writable_as_buf(&cln->_req_rw, buf);
        return;
    }

    ah_http_res_t* res = ah_i_http_res_queue_peek(&cln->_res_queue);
    if (res == NULL) {
        err = AH_ESTATE;
        code = 500u;
        goto close_conn_and_report_err_code;
    }

    cln->_vtab->on_msg_alloc(cln, buf, true, res);
    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
        return;
    }
    if (ah_buf_is_empty(buf)) {
        err = AH_ENOBUFS;
        code = 503u;
        goto close_conn_and_report_err_code;
    }

    ah_buf_rw_init_for_writing_to(&cln->_req_rw, buf);

    return;

close_conn_and_report_err_code:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_req_end(cln, err, code, NULL);
}

static void s_on_conn_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread, ah_err_t err)
{
    ah_http_rclient_t* cln = ah_i_http_upcast_to_rclient(conn);

    uint16_t code = AH_HTTP_CODE_INTERNAL_SERVER_ERROR;

    if (err != AH_ENONE) {
        goto close_conn_and_report_err;
    }

    ah_assert_if_debug(cln->_req_rw.wr == ah_buf_get_base_const(buf));
    (void) buf;

    if (!ah_buf_rw_juken(&cln->_req_rw, nread)) {
        err = AH_EDOM;
        goto close_conn_and_report_err;
    }

    switch (cln->_req_state) {
    case S_REQ_STATE_INIT: {
        if (ah_i_http_res_queue_is_empty(&cln->_res_queue)) {
            err = AH_ESTATE;
            goto close_conn_and_report_err;
        }

        cln->_req_state = S_REQ_STATE_LINE;
        goto state_req_line;
    }

    state_req_line:
    case S_REQ_STATE_LINE: {
        ah_http_req_line_t req_line;
        err = ah_i_http_parse_req_line(&cln->_req_rw, &req_line);
        if (err != AH_ENONE) {
            if (err == AH_EEOF) {
                code = AH_HTTP_CODE_URI_TOO_LONG;
                err = AH_EOVERFLOW; // Current buffer not large enough to hold request line.
            }
            goto close_conn_and_report_err;
        }

        cln->_vtab->on_req_line(cln, req_line, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_req_state = S_REQ_STATE_HEADERS;
        goto state_headers;
    }

    state_headers:
    case S_REQ_STATE_HEADERS: {
        bool has_connection_close_been_seen = false;
        bool has_content_length_been_seen = false;
        bool has_transfer_encoding_chunked_been_seen = false;
        size_t content_length;

        ah_http_res_t* res = ah_i_http_res_queue_peek_unsafe(&cln->_res_queue);

        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_req_rw, &header);
            if (err != AH_ENONE) {
                if (err == AH_EEOF) {
                    code = AH_HTTP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE;
                    err = AH_EOVERFLOW; // Current buffer not large enough to hold all headers.
                }
                goto close_conn_and_report_err;
            }

            if (header.name == NULL) {
                if (cln->_vtab->on_req_headers != NULL) {
                    cln->_vtab->on_req_headers(cln, res);
                    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                        return;
                    }
                }

                if (has_transfer_encoding_chunked_been_seen) {
                    if (has_content_length_been_seen && content_length != 0u) {
                        code = AH_HTTP_CODE_BAD_REQUEST;
                        err = AH_EBADMSG;
                        goto close_conn_and_report_err;
                    }
                    cln->_req_state = S_REQ_STATE_CHUNK_LINE;
                    goto state_chunk_line;
                }

                if (!has_content_length_been_seen || content_length == 0u) {
                    goto state_end;
                }

                cln->_req_n_expected_bytes = content_length;
                cln->_req_state = S_REQ_STATE_DATA;
                goto state_data;
            }

            if (ah_i_http_header_name_eq("content-length", header.name)) {
                if (has_content_length_been_seen) {
                    code = AH_HTTP_CODE_BAD_REQUEST;
                    err = AH_EDUP;
                    goto close_conn_and_report_err;
                }
                err = ah_i_http_header_value_to_size(header.value, &content_length);
                if (err != AH_ENONE) {
                    code = AH_HTTP_CODE_BAD_REQUEST;
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
                        code = AH_HTTP_CODE_BAD_REQUEST;
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
            else if (!has_connection_close_been_seen && ah_i_http_header_name_eq("connection", header.name)) {
                // The "connection" header itself and its defined values are
                // permitted to occur more than once. See
                // https://datatracker.ietf.org/doc/html/rfc7230#section-6.3.
                if (ah_i_http_header_value_has_csv(header.value, "close", NULL)) {
                    cln->_keep_alive = false;
                    has_connection_close_been_seen = true;
                }
                else if (res->stat_line.version.minor == 0u) {
                    if (ah_i_http_header_value_has_csv(header.value, "keep-alive", NULL)) {
                        cln->_keep_alive = true;
                    }
                }
            }

            cln->_vtab->on_req_header(cln, header, res);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_chunk_line:
    case S_REQ_STATE_CHUNK_LINE: {
        ah_http_chunk_line_t chunk_line;

        err = ah_i_http_parse_chunk_line(&cln->_req_rw, &chunk_line);
        if (err != AH_ENONE) {
            if (err != AH_EEOF) {
                code = AH_HTTP_CODE_BAD_REQUEST;
                goto close_conn_and_report_err;
            }
            if (cln->_prohibit_realloc) {
                code = AH_HTTP_CODE_BAD_REQUEST;
                err = AH_EOVERFLOW; // Newly allocated buffer not large enough to hold chunk line.
                goto close_conn_and_report_err;
            }
            err = s_realloc_res_rw(cln);
            if (err != AH_ENONE) {
                code = AH_HTTP_CODE_INSUFFICIENT_STORAGE;
                goto close_conn_and_report_err;
            }
            cln->_prohibit_realloc = true;
            return;
        }
        cln->_prohibit_realloc = false;

        if (cln->_vtab->on_req_chunk_line != NULL) {
            cln->_vtab->on_req_chunk_line(cln, chunk_line, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }

        if (chunk_line.size == 0u) {
            ah_assert_if_debug(cln->_req_n_expected_bytes == 0u);
            cln->_req_state = S_REQ_STATE_TRAILER;
            goto state_trailer;
        }

        cln->_req_n_expected_bytes = chunk_line.size;
        cln->_req_state = S_REQ_STATE_CHUNK_DATA;
        goto state_chunk_data;
    }

    state_data:
    state_chunk_data:
    case S_REQ_STATE_DATA:
    case S_REQ_STATE_CHUNK_DATA: {
        ah_buf_t readable_buf;
        ah_buf_rw_get_readable_as_buf(&cln->_req_rw, &readable_buf);

        ah_buf_limit_size_to(&readable_buf, cln->_req_n_expected_bytes);
        cln->_req_n_expected_bytes -= ah_buf_get_size(&readable_buf);

        cln->_vtab->on_req_data(cln, &readable_buf, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        if (cln->_req_n_expected_bytes == 0u) {
            if (cln->_req_state == S_REQ_STATE_DATA) {
                goto state_end;
            }
            cln->_req_state = S_REQ_STATE_CHUNK_LINE;
            goto state_chunk_line;
        }

        return;
    }

    state_trailer:
    case S_REQ_STATE_TRAILER: {
        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_req_rw, &header);
            if (err != AH_ENONE) {
                if (err != AH_EEOF) {
                    code = AH_HTTP_CODE_BAD_REQUEST;
                    goto close_conn_and_report_err;
                }
                if (cln->_prohibit_realloc) {
                    code = AH_HTTP_CODE_REQUEST_HEADER_FIELDS_TOO_LARGE;
                    err = AH_EOVERFLOW; // Newly allocated buffer not large enough to hold headers.
                    goto close_conn_and_report_err;
                }
                err = s_realloc_res_rw(cln);
                if (err != AH_ENONE) {
                    code = AH_HTTP_CODE_INSUFFICIENT_STORAGE;
                    goto close_conn_and_report_err;
                }
                cln->_prohibit_realloc = true;
                return;
            }

            if (header.name == NULL) {
                cln->_prohibit_realloc = false;
                goto state_end;
            }

            cln->_vtab->on_req_header(cln, header, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_end : {
        cln->_vtab->on_req_end(cln, AH_ENONE, 0u, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        ah_i_http_res_queue_discard_unsafe(&cln->_res_queue);

        if (!cln->_keep_alive) {
            err = cln->_trans_vtab->conn_close(conn);
            if (err != AH_ENONE) {
                goto report_err;
            }
        }

        if (ah_i_http_res_queue_is_empty(&cln->_res_queue)) {
            if (ah_buf_rw_get_readable_size(&cln->_req_rw) != 0u) {
                err = AH_ESTATE;
                goto close_conn_and_report_err;
            }
            cln->_req_state = S_REQ_STATE_INIT;
            return;
        }

        cln->_req_state = S_REQ_STATE_LINE;
        goto state_req_line;
    }

    default:
        ah_unreachable();
    }

close_conn_and_report_err:
    if (!ah_tcp_conn_is_closed(conn)) {
        (void) cln->_trans_vtab->conn_close(conn);
    }
report_err:
    cln->_vtab->on_req_end(cln, err, code, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
}

static ah_err_t s_realloc_res_rw(ah_http_rclient_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    ah_buf_t new_buf;
    cln->_vtab->on_msg_alloc(cln, &new_buf, false, ah_i_http_res_queue_peek_unsafe(&cln->_res_queue));
    if (ah_buf_is_empty(&new_buf)) {
        return AH_ENOBUFS;
    }

    ah_buf_rw_t new_rw;
    ah_buf_rw_init_for_writing_to(&new_rw, &new_buf);

    if (!ah_buf_rw_copyn(&cln->_req_rw, &new_rw, ah_buf_rw_get_readable_size(&cln->_req_rw))) {
        return AH_EOVERFLOW;
    }

    cln->_req_rw = new_rw;

    return AH_ENONE;
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

    ah_http_res_t* res = ah_i_http_res_queue_peek(&cln->_res_queue);
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

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_rclient_send_end(ah_http_rclient_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }

    ah_http_res_t* res = ah_i_http_res_queue_peek_unsafe(&cln->_res_queue);

    if (res->body._as_any._kind != AH_I_HTTP_BODY_KIND_OVERRIDE) {
        return AH_ESTATE;
    }

    res->body._as_any._kind = AH_I_HTTP_BODY_KIND_EMPTY;

    if (res->_n_pending_tcp_msgs > 0u) {
        return AH_ENONE;
    }

    // s_complete_current_res(cln, AH_ENONE);

    return AH_EOPNOTSUPP; // TODO: Finish implementation.
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
