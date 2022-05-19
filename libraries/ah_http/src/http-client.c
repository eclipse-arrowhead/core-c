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
#include <ah/math.h>
#include <ah/sock.h>

// Incoming message states.
#define S_IN_STATE_INIT       0x01
#define S_IN_STATE_LINE       0x02
#define S_IN_STATE_HEADERS    0x04
#define S_IN_STATE_DATA       0x08
#define S_IN_STATE_CHUNK_LINE 0x10
#define S_IN_STATE_CHUNK_DATA 0x20
#define S_IN_STATE_TRAILER    0x40

#define S_IN_STATE_IS_REUSING_BUF_RW(STATE) \
 (((STATE) & (S_IN_STATE_LINE | S_IN_STATE_HEADERS | S_IN_STATE_CHUNK_LINE | S_IN_STATE_TRAILER)) != 0u)

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static void s_complete_current_msg(ah_http_client_t* cln, ah_err_t err);
static void s_write_msg(ah_http_client_t* cln);
static ah_err_t s_realloc_res_rw(ah_http_client_t* cln);

static bool s_write_crlf(ah_buf_rw_t* rw);
static bool s_write_cstr(ah_buf_rw_t* rw, const char* cstr);
static bool s_write_size_as_string(ah_buf_rw_t* rw, size_t size, unsigned base);

static const ah_tcp_conn_vtab_t s_vtab = {
    .on_open = s_on_open,
    .on_connect = s_on_connect,
    .on_close = s_on_close,
    .on_read_alloc = s_on_read_alloc,
    .on_read_data = s_on_read_data,
    .on_write_done = s_on_write_done,
};

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
    ah_assert_if_debug(vtab->on_alloc != NULL);
    ah_assert_if_debug(vtab->on_send_done != NULL);
    ah_assert_if_debug(vtab->on_recv_line != NULL);
    ah_assert_if_debug(vtab->on_recv_header != NULL);
    ah_assert_if_debug(vtab->on_recv_data != NULL);
    ah_assert_if_debug(vtab->on_recv_end != NULL);

    ah_err_t err = trans._vtab->conn_init(&cln->_conn, trans._loop, &s_vtab);
    if (err != AH_ENONE) {
        return err;
    }

    cln->_conn._trans_data = trans._data;
    cln->_trans_vtab = trans._vtab;
    cln->_vtab = vtab;

    cln->_in_state = S_IN_STATE_INIT;

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
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);
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
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);
    cln->_vtab->on_connect(cln, err);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    ah_err_t err;

    if (S_IN_STATE_IS_REUSING_BUF_RW(cln->_in_state)) {
        ah_buf_rw_get_writable_as_buf(&cln->_in_buf_rw, buf);
        return;
    }

    if (cln->_in_n_expected_msgs == 0u) {
        err = AH_ESTATE;
        goto report_err_and_close_conn;
    }

    cln->_vtab->on_alloc(cln, buf, true);
    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
        return;
    }
    if (ah_buf_is_empty(buf)) {
        err = AH_ENOBUFS;
        goto report_err_and_close_conn;
    }

    ah_buf_rw_init_for_writing_to(&cln->_in_buf_rw, buf);

    return;

report_err_and_close_conn:
    cln->_vtab->on_recv_end(cln, err);
    cln->_trans_vtab->conn_close(conn);
}

static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    if (err != AH_ENONE) {
        goto report_err_and_close_conn;
    }

    ah_assert_if_debug(cln->_in_buf_rw.wr == ah_buf_get_base_const(buf));
    (void) buf;

    if (!ah_buf_rw_juken(&cln->_in_buf_rw, nread)) {
        err = AH_EDOM;
        goto report_err_and_close_conn;
    }

    switch (cln->_in_state) {
    case S_IN_STATE_INIT: {
        if (cln->_in_n_expected_msgs == 0u) {
            err = AH_ESTATE;
            goto report_err_and_close_conn;
        }

        cln->_in_state = S_IN_STATE_LINE;
        goto state_stat_line;
    }

    state_stat_line:
    case S_IN_STATE_LINE: {
        const char* line;
        ah_http_ver_t version;
        err = cln->_is_accepted
            ? ah_i_http_parse_req_line(&cln->_in_buf_rw, &line, &version)
            : ah_i_http_parse_stat_line(&cln->_in_buf_rw, &line, &version);
        if (err != AH_ENONE) {
            if (err == AH_EEOF) {
                err = AH_EOVERFLOW; // Current buffer not large enough to hold request/status line.
            }
            goto report_err_and_close_conn;
        }

        cln->_vtab->on_recv_line(cln, line, version);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_in_state = S_IN_STATE_HEADERS;
        goto state_headers;
    }

    state_headers:
    case S_IN_STATE_HEADERS: {
        bool has_connection_close_been_seen = false;
        bool has_content_length_been_seen = false;
        bool has_transfer_encoding_chunked_been_seen = false;
        size_t content_length;

        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_in_buf_rw, &header);
            if (err != AH_ENONE) {
                if (err == AH_EEOF) {
                    err = AH_EOVERFLOW; // Current buffer not large enough to hold all headers.
                }
                goto report_err_and_close_conn;
            }

            if (header.name == NULL) {
                if (cln->_vtab->on_recv_headers != NULL) {
                    cln->_vtab->on_recv_headers(cln);
                    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                        return;
                    }
                }

                if (has_transfer_encoding_chunked_been_seen) {
                    if (has_content_length_been_seen && content_length != 0u) {
                        err = AH_EBADMSG;
                        goto report_err_and_close_conn;
                    }
                    cln->_in_state = S_IN_STATE_CHUNK_LINE;
                    goto state_chunk_line;
                }

                if (!has_content_length_been_seen || content_length == 0u) {
                    goto state_end;
                }

                cln->_in_n_expected_bytes = content_length;
                cln->_in_state = S_IN_STATE_DATA;
                goto state_data;
            }

            if (ah_i_http_header_name_eq("content-length", header.name)) {
                if (has_content_length_been_seen) {
                    err = AH_EDUP;
                    goto report_err_and_close_conn;
                }
                err = ah_i_http_header_value_to_size(header.value, &content_length);
                if (err != AH_ENONE) {
                    goto report_err_and_close_conn;
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
                        goto report_err_and_close_conn;
                    }

                    if (has_transfer_encoding_chunked_been_seen) {
                        err = AH_EDUP;
                        goto report_err_and_close_conn;
                    }
                    has_transfer_encoding_chunked_been_seen = true;
                    break;

                case AH_ESRCH:
                    break;

                default:
                    goto report_err_and_close_conn;
                }
            }
            else if (!has_connection_close_been_seen && ah_i_http_header_name_eq("connection", header.name)) {
                // The "connection" header itself and its defined values are
                // permitted to occur more than once. See
                // https://datatracker.ietf.org/doc/html/rfc7230#section-6.3.
                if (ah_i_http_header_value_has_csv(header.value, "close", NULL)) {
                    cln->_is_keeping_connection_open = false;
                    has_connection_close_been_seen = true;
                }
                else if (ah_i_http_header_value_has_csv(header.value, "keep-alive", NULL)) {
                    cln->_is_keeping_connection_open = true;
                }
            }

            cln->_vtab->on_recv_header(cln, header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_chunk_line:
    case S_IN_STATE_CHUNK_LINE: {
        size_t size;
        const char* ext;

        err = ah_i_http_parse_chunk_line(&cln->_in_buf_rw, &size, &ext);
        if (err != AH_ENONE) {
            if (err != AH_EEOF) {
                goto report_err_and_close_conn;
            }
            if (cln->_is_preventing_realloc) {
                err = AH_EOVERFLOW; // Newly allocated buffer not large enough to hold chunk line.
                goto report_err_and_close_conn;
            }
            err = s_realloc_res_rw(cln);
            if (err != AH_ENONE) {
                goto report_err_and_close_conn;
            }
            cln->_is_preventing_realloc = true;
            return;
        }
        cln->_is_preventing_realloc = false;

        if (cln->_vtab->on_recv_chunk_line != NULL) {
            cln->_vtab->on_recv_chunk_line(cln, size, ext);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }

        if (size == 0u) {
            ah_assert_if_debug(cln->_in_n_expected_bytes == 0u);
            cln->_in_state = S_IN_STATE_TRAILER;
            goto state_trailer;
        }

        cln->_in_n_expected_bytes = size;
        cln->_in_state = S_IN_STATE_CHUNK_DATA;
        goto state_chunk_data;
    }

    state_data:
    state_chunk_data:
    case S_IN_STATE_DATA:
    case S_IN_STATE_CHUNK_DATA: {
        ah_buf_t readable_buf;
        ah_buf_rw_get_readable_as_buf(&cln->_in_buf_rw, &readable_buf);

        ah_buf_limit_size_to(&readable_buf, cln->_in_n_expected_bytes);
        cln->_in_n_expected_bytes -= ah_buf_get_size(&readable_buf);

        cln->_vtab->on_recv_data(cln, &readable_buf);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        if (cln->_in_n_expected_bytes == 0u) {
            if (cln->_in_state == S_IN_STATE_DATA) {
                goto state_end;
            }
            cln->_in_state = S_IN_STATE_CHUNK_LINE;
            goto state_chunk_line;
        }

        return;
    }

    state_trailer:
    case S_IN_STATE_TRAILER: {
        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_in_buf_rw, &header);
            if (err != AH_ENONE) {
                if (err != AH_EEOF) {
                    goto report_err_and_close_conn;
                }
                if (cln->_is_preventing_realloc) {
                    err = AH_EOVERFLOW; // Newly allocated buffer not large enough to hold headers.
                    goto report_err_and_close_conn;
                }
                err = s_realloc_res_rw(cln);
                if (err != AH_ENONE) {
                    goto report_err_and_close_conn;
                }
                cln->_is_preventing_realloc = true;
                return;
            }

            if (header.name == NULL) {
                cln->_is_preventing_realloc = false;
                goto state_end;
            }

            cln->_vtab->on_recv_header(cln, header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_end : {
        cln->_vtab->on_recv_end(cln, AH_ENONE);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        ah_assert_if_debug(cln->_in_n_expected_msgs > 0u);
        cln->_in_n_expected_msgs -= 1u;

        if (!cln->_is_keeping_connection_open) {
            err = cln->_trans_vtab->conn_close(conn);
            if (err != AH_ENONE) {
                goto report_err_and_close_conn;
            }
        }

        if (cln->_in_n_expected_msgs == 0u) {
            if (ah_buf_rw_get_readable_size(&cln->_in_buf_rw) != 0u) {
                err = AH_ESTATE;
                goto report_err_and_close_conn;
            }
            cln->_in_state = S_IN_STATE_INIT;
            return;
        }

        cln->_in_state = S_IN_STATE_LINE;
        goto state_stat_line;
    }

    default:
        ah_unreachable();
    }

report_err_and_close_conn:
    cln->_vtab->on_recv_end(cln, err);
    if (!ah_tcp_conn_is_closed(conn)) {
        (void) cln->_trans_vtab->conn_close(conn);
    }
}

static ah_err_t s_realloc_res_rw(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    ah_buf_t new_buf;
    cln->_vtab->on_alloc(cln, &new_buf, false);
    if (ah_buf_is_empty(&new_buf)) {
        return AH_ENOBUFS;
    }

    ah_buf_rw_t new_rw;
    ah_buf_rw_init_for_writing_to(&new_rw, &new_buf);

    if (!ah_buf_rw_copyn(&cln->_in_buf_rw, &new_rw, ah_buf_rw_get_readable_size(&cln->_in_buf_rw))) {
        return AH_EOVERFLOW;
    }

    cln->_in_buf_rw = new_rw;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_send(ah_http_client_t* cln, ah_http_msg_t* msg)
{
    if (cln == NULL || msg == NULL) {
        return AH_EINVAL;
    }
    if (msg->version.major != 1u || msg->version.minor > 9u) {
        return AH_EPROTONOSUPPORT;
    }

    if (ah_i_http_msg_queue_is_empty_then_add(&cln->_out_queue, msg)) {
        s_write_msg(cln);
    }

    return AH_ENONE;
}

static void s_write_msg(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    ah_err_t err;
    ah_http_header_t* header;
    ah_http_msg_t* msg;

try_next:
    msg = ah_i_http_msg_queue_peek_unsafe(&cln->_out_queue);

    cln->_is_keeping_connection_open = msg->version.minor != 0u;
    cln->_is_preventing_realloc = false;

    cln->_vtab->on_alloc(cln, &msg->_head_buf, true);
    if (ah_buf_is_empty(&msg->_head_buf)) {
        err = AH_ENOBUFS;
        goto report_err_and_try_next;
    }

    ah_buf_rw_t rw;
    ah_buf_rw_init_for_writing_to(&rw, &msg->_head_buf);

    // Write request/status line to head buffer.
    if (cln->_is_accepted) {
        (void) s_write_cstr(&rw, msg->line);
    }
    (void) s_write_cstr(&rw, " HTTP/1.");
    (void) ah_buf_rw_write1(&rw, '0' + msg->version.minor);
    if (!cln->_is_accepted) {
        (void) ah_buf_rw_write1(&rw, ' ');
        (void) s_write_cstr(&rw, msg->line);
    }
    (void) s_write_crlf(&rw);

    // Write host header to head buffer, if HTTP version is 1.1 or above and
    // no such header has been provided.
    if (!cln->_is_accepted && msg->version.minor != 0u) {
        bool host_is_not_specified = true;
        if (msg->headers != NULL) {
            for (header = &msg->headers[0u]; header->name != NULL; header = &header[1u]) {
                if (ah_i_http_header_name_eq("host", header->name)) {
                    host_is_not_specified = false;
                    break;
                }
            }
        }

        if (host_is_not_specified) {
            (void) s_write_cstr(&rw, "host:");

            ah_sockaddr_t raddr = *cln->_raddr;
            if (raddr.as_any.family == AH_SOCKFAMILY_IPV6 && raddr.as_ipv6.zone_id != 0u) {
                raddr.as_ipv6.zone_id = 0u;
            }

            ah_buf_t buf;
            ah_buf_rw_get_writable_as_buf(&rw, &buf);

            size_t nwritten = ah_buf_get_size(&buf);
            err = ah_sockaddr_stringify(&raddr, (char*) ah_buf_get_base(&buf), &nwritten);
            if (err != AH_ENONE) {
                goto report_err_and_try_next;
            }
            (void) ah_buf_rw_juken(&rw, nwritten);

            (void) s_write_crlf(&rw);
        }
    }

    // Write other headers to head buffer.
    if (msg->headers != NULL) {
        for (header = &msg->headers[0u]; header->name != NULL; header = &header[1u]) {
            (void) s_write_cstr(&rw, header->name);
            (void) ah_buf_rw_write1(&rw, ':');
            (void) s_write_cstr(&rw, header->value);
            (void) s_write_crlf(&rw);
        }
    }

    // Write content-length header to head buffer and prepare message payload (if any).
    size_t content_length;
    switch (msg->body._as_any._kind) {
    case AH_I_HTTP_BODY_KIND_EMPTY:
    case AH_I_HTTP_BODY_KIND_OVERRIDE:
        content_length = 0u;
        goto headers_end;

    case AH_I_HTTP_BODY_KIND_BUF:
        content_length = msg->body._as_buf._buf._size;
        err = ah_tcp_msg_init(&msg->_body_msg, (ah_bufs_t) { .items = &msg->body._as_buf._buf, .length = 1u });
        if (ah_unlikely(err != AH_ENONE)) {
            goto report_err_and_try_next;
        }
        break;

    case AH_I_HTTP_BODY_KIND_BUFS:
        content_length = 0u;
        for (size_t i = 0u; i < msg->body._as_bufs._bufs.length; i += 1u) {
            err = ah_add_size(content_length, msg->body._as_bufs._bufs.items[i]._size, &content_length);
            if (ah_unlikely(err != AH_ENONE)) {
                goto report_err_and_try_next;
            }
        }
        err = ah_tcp_msg_init(&msg->_body_msg, msg->body._as_bufs._bufs);
        if (ah_unlikely(err != AH_ENONE)) {
            goto report_err_and_try_next;
        }
        break;

    default:
        ah_unreachable();
    }
    (void) s_write_cstr(&rw, "content-length:");
    (void) s_write_size_as_string(&rw, content_length, 10u);
    (void) s_write_crlf(&rw);

headers_end:
    if (!s_write_crlf(&rw)) {
        err = AH_EOVERFLOW;
        goto report_err_and_try_next;
    }

    // Prepare message with request line and headers.
    err = ah_tcp_msg_init(&msg->_head_msg, (ah_bufs_t) { .items = &msg->_head_buf, .length = 1u });
    if (ah_unlikely(err != AH_ENONE)) {
        goto report_err_and_try_next;
    }

    // Send message with request line and headers.
    err = cln->_trans_vtab->conn_write(&cln->_conn, &msg->_head_msg);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }
    msg->_n_pending_tcp_msgs = 1u;

    // Send message with body, if any.
    if (content_length != 0u) {
        err = cln->_trans_vtab->conn_write(&cln->_conn, &msg->_body_msg);
        if (err != AH_ENONE) {
            goto report_err_and_try_next;
        }
        msg->_n_pending_tcp_msgs += 1u;
    }

    return;

report_err_and_try_next:
    msg = ah_i_http_msg_queue_remove_unsafe(&cln->_out_queue);

    cln->_vtab->on_send_done(cln, msg, err);
    if (!ah_tcp_conn_is_writable(&cln->_conn)) {
        return;
    }

    if (ah_i_http_msg_queue_is_empty(&cln->_out_queue)) {
        return;
    }

    goto try_next;
}

static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    ah_http_msg_t* msg = ah_i_http_msg_queue_peek_unsafe(&cln->_out_queue);

    if (err == AH_ENONE) {
        ah_assert_if_debug(msg->_n_pending_tcp_msgs > 0u);
        msg->_n_pending_tcp_msgs -= 1u;
        if (msg->_n_pending_tcp_msgs != 0u || msg->body._as_any._kind == AH_I_HTTP_BODY_KIND_OVERRIDE) {
            return;
        }
    }

    s_complete_current_msg(cln, err);
}

static void s_complete_current_msg(ah_http_client_t* cln, ah_err_t err)
{
    ah_http_msg_t* msg = ah_i_http_msg_queue_remove_unsafe(&cln->_out_queue);

    cln->_vtab->on_send_done(cln, msg, err);
    if (!ah_tcp_conn_is_writable(&cln->_conn)) {
        return;
    }

    if (err == AH_ENONE) {
        cln->_in_n_expected_msgs += 1u;
    }

    if (ah_i_http_msg_queue_is_empty(&cln->_out_queue)) {
        return;
    }

    s_write_msg(cln);
}

ah_extern ah_err_t ah_http_client_send_data(ah_http_client_t* cln, ah_tcp_msg_t* msg)
{
    if (cln == NULL || msg == NULL) {
        return AH_EINVAL;
    }

    ah_http_msg_t* req = ah_i_http_msg_queue_peek(&cln->_out_queue);
    if (req == NULL) {
        return AH_ESTATE;
    }

    if (req->body._as_any._kind != AH_I_HTTP_BODY_KIND_OVERRIDE) {
        return AH_ESTATE;
    }

    ah_err_t err = cln->_trans_vtab->conn_write(&cln->_conn, msg);
    if (err != AH_ENONE) {
        return err;
    }

    req->_n_pending_tcp_msgs += 1u;

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_send_end(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }

    ah_http_msg_t* req = ah_i_http_msg_queue_peek(&cln->_out_queue);
    if (req == NULL) {
        return AH_ESTATE;
    }

    if (req->body._as_any._kind != AH_I_HTTP_BODY_KIND_OVERRIDE) {
        return AH_ESTATE;
    }

    req->body._as_any._kind = AH_I_HTTP_BODY_KIND_EMPTY;

    if (req->_n_pending_tcp_msgs > 0u) {
        return AH_ENONE;
    }

    s_complete_current_msg(cln, AH_ENONE);

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_send_chunk(ah_http_client_t* cln, ah_http_chunk_t* chunk)
{
    if (cln == NULL || chunk == NULL) {
        return AH_EINVAL;
    }
#ifndef NDEBUG
    if (chunk->ext != NULL && chunk->ext[0u] != '\0' && chunk->ext[0u] != ';') {
        return AH_EILSEQ;
    }
#endif

    ah_err_t err;

    ah_http_msg_t* req = ah_i_http_msg_queue_peek(&cln->_out_queue);
    if (req == NULL) {
        return AH_ESTATE;
    }

    // Calculate the size of the chunk.
    size_t chunk_size = 0u;
    ah_bufs_t bufs = ah_tcp_msg_unwrap(&chunk->data);
    for (size_t i = 0u; i < bufs.length; i += 1u) {
        err = ah_add_size(chunk_size, ah_buf_get_size(&bufs.items[i]), &chunk_size);
        if (ah_unlikely(err != AH_ENONE)) {
            goto report_err_and_try_next;
        }
    }

    // Allocate chunk line buffer.
    cln->_vtab->on_alloc(cln, &chunk->_line_buf, true);
    if (ah_buf_is_empty(&chunk->_line_buf)) {
        err = AH_ENOBUFS;
        goto report_err_and_try_next;
    }

    ah_buf_rw_t rw;
    ah_buf_rw_init_for_writing_to(&rw, &chunk->_line_buf);

    // Write chunk line to buffer.
    (void) s_write_size_as_string(&rw, chunk_size, 16u);
    if (chunk->ext != NULL) {
        (void) s_write_cstr(&rw, chunk->ext);
    }
    if (!s_write_crlf(&rw)) {
        err = AH_EOVERFLOW;
        goto report_err_and_try_next;
    }

    // Prepare message with chunk line.
    err = ah_tcp_msg_init(&chunk->_line_msg, (ah_bufs_t) { .items = &chunk->_line_buf, .length = 1u });
    if (ah_unlikely(err != AH_ENONE)) {
        goto report_err_and_try_next;
    }

    // Send message with chunk line.
    err = cln->_trans_vtab->conn_write(&cln->_conn, &chunk->_line_msg);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }
    req->_n_pending_tcp_msgs += 1u;

    // Send message with data.
    err = cln->_trans_vtab->conn_write(&cln->_conn, &chunk->data);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }
    req->_n_pending_tcp_msgs += 1u;

    return AH_ENONE;

report_err_and_try_next:
    s_complete_current_msg(cln, err);
    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_send_trailer(ah_http_client_t* cln, ah_http_trailer_t* trailer)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
#ifndef NDEBUG
    if (trailer->ext != NULL && trailer->ext[0u] != '\0' && trailer->ext[0u] != ';') {
        return AH_EILSEQ;
    }
#endif

    ah_err_t err;

    ah_http_msg_t* req = ah_i_http_msg_queue_peek(&cln->_out_queue);
    if (req == NULL) {
        return AH_ESTATE;
    }

    // Allocate trailer buffer.
    cln->_vtab->on_alloc(cln, &trailer->_buf, true);
    if (ah_buf_is_empty(&trailer->_buf)) {
        err = AH_ENOBUFS;
        goto report_err_and_try_next;
    }

    ah_buf_rw_t rw;
    ah_buf_rw_init_for_writing_to(&rw, &trailer->_buf);

    // Write trailer chunk line to buffer.
    (void) ah_buf_rw_write1(&rw, '0');
    if (trailer->ext != NULL) {
        (void) s_write_cstr(&rw, trailer->ext);
    }
    if (!s_write_crlf(&rw)) {
        err = AH_EOVERFLOW;
        goto report_err_and_try_next;
    }

    // Write trailer headers to buffer.
    if (trailer->headers != NULL) {
        ah_http_header_t* header = &trailer->headers[0u];
        for (; header->name != NULL; header = &header[1u]) {
            (void) s_write_cstr(&rw, header->name);
            (void) ah_buf_rw_write1(&rw, ':');
            (void) s_write_cstr(&rw, header->value);
            (void) s_write_crlf(&rw);
        }
    }
    (void) s_write_crlf(&rw);

    // Prepare message with complete trailer.
    err = ah_tcp_msg_init(&trailer->_msg, (ah_bufs_t) { .items = &trailer->_buf, .length = 1u });
    if (ah_unlikely(err != AH_ENONE)) {
        goto report_err_and_try_next;
    }

    // Send message with complete trailer.
    err = cln->_trans_vtab->conn_write(&cln->_conn, &trailer->_msg);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }
    req->_n_pending_tcp_msgs += 1u;

    return ah_http_client_send_end(cln);

report_err_and_try_next:
    s_complete_current_msg(cln, err);
    return AH_ENONE;
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
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    for (ah_http_msg_t* msg;;) {
        msg = ah_i_http_msg_queue_remove(&cln->_out_queue);
        if (msg == NULL) {
            break;
        }
        cln->_vtab->on_send_done(cln, msg, AH_ECANCELED);
    }

    cln->_vtab->on_close(cln, err);
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

void ah_i_http_client_init_accepted(ah_http_client_t* cln, ah_http_server_t* srv, const ah_sockaddr_t* raddr)
{
    ah_assert_if_debug(cln != NULL);
    ah_assert_if_debug(!ah_tcp_conn_is_closed(&cln->_conn));
    ah_assert_if_debug(srv != NULL);
    ah_assert_if_debug(raddr != NULL);

    cln->_raddr = raddr;
    cln->_trans_vtab = srv->_trans_vtab;
    cln->_vtab = srv->_client_vtab;
    cln->_out_queue = (struct ah_i_http_msg_queue) { 0u };
    cln->_in_state = S_IN_STATE_INIT;
}

const ah_tcp_conn_vtab_t* ah_i_http_client_get_conn_vtab()
{
    return &s_vtab;
}

static bool s_write_crlf(ah_buf_rw_t* rw) {
    ah_assert_if_debug(rw != NULL);

    if ((rw->end - rw->wr) < 2u) {
        return false;
    }

    rw->wr[0u] = '\r';
    rw->wr[1u] = '\n';
    rw->wr = &rw->wr[2u];

    return true;
}

static bool s_write_cstr(ah_buf_rw_t* rw, const char* cstr)
{
    ah_assert_if_debug(rw != NULL);

    const uint8_t* c = (const uint8_t*) cstr;
    uint8_t* wr = rw->wr;

    while (wr != rw->end) {
        if (c[0u] == '\0') {
            rw->wr = wr;
            return true;
        }

        wr[0u] = c[0u];

        wr = &wr[1u];
        c = &c[1u];
    }

    return false;
}

static bool s_write_size_as_string(ah_buf_rw_t* rw, size_t size, unsigned base)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(base >= 10u && base <= 16u);

    if (size == 0u)  {
        return ah_buf_rw_write1(rw, '0');
    }

    uint8_t buf[20];
    uint8_t* off = &buf[sizeof(buf) - 1u];
    const uint8_t* end = off;

    uint64_t s = size;
    for (;;) {
        uint8_t digit = s % base;
        if (digit < 10u) {
            off[0u] = '0' + digit;
        }
        else {
            off[0u] = 'A' + digit - 10u;
        }
        s /= base;
        if (s == 0u) {
            break;
        }
        off = &off[-1];
    }

    return ah_buf_rw_writen(rw, off, (size_t) (end - off));
}
