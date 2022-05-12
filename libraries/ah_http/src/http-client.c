// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"

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

// Response state categories.
#define S_RES_STATE_CATEGORY_REUSE_BUF_RW \
 (S_RES_STATE_STAT_LINE | S_RES_STATE_HEADERS | S_RES_STATE_CHUNK_LINE | S_RES_STATE_TRAILER)

// Output (request) states.
#define S_O_STATE_READY        0u
#define S_O_STATE_SENDING_HEAD 1u
#define S_O_STATE_SENDING_BODY 2u

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static bool s_cstr_is_eq_ignore_case_ascii(const char* a, const char* b);
static ah_err_t s_find_transfer_encoding_chunked_in(const char* cstr);
static ah_err_t s_parse_content_length(const char* cstr, size_t* value);
static uint8_t s_to_lower_ascii(uint8_t ch);

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);

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

    const ah_tcp_conn_vtab_t s_vtab = {
        .on_open = (void (*)(ah_tcp_conn_t*, ah_err_t)) cln->_vtab->on_open,
        .on_connect = (void (*)(ah_tcp_conn_t*, ah_err_t)) cln->_vtab->on_connect,
        .on_close = (void (*)(ah_tcp_conn_t*, ah_err_t)) cln->_vtab->on_close,
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

ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_connect(&cln->_conn, raddr);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    ah_err_t err;

    if ((cln->_res_state & S_RES_STATE_CATEGORY_REUSE_BUF_RW) != 0) {
        ah_buf_rw_get_writable_as_buf(&cln->_res_buf_rw, buf);
        return;
    }

    ah_http_req_t* req = cln->_req_queue._head;
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
        if (cln->_req_queue._head == NULL) {
            err = AH_ESTATE;
            goto close_conn_and_report_err;
        }

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

        ah_assert_if_debug(cln->_req_queue._head != NULL);
        cln->_vtab->on_res_stat_line(cln, cln->_req_queue._head, &stat_line);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_res_state = S_RES_STATE_HEADERS;
        goto state_headers;
    }

    state_headers:
    case S_RES_STATE_HEADERS: {
        bool has_content_length_been_seen = false;
        bool has_transfer_encoding_chunked_been_seen = false;
        size_t content_length;

        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&cln->_res_buf_rw, &header);
            if (err != AH_ENONE) {
                break;
            }

            if (header.name == NULL) {
                if (cln->_vtab->on_res_headers != NULL) {
                    cln->_vtab->on_res_headers(cln, cln->_req_queue._head);
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

            if (s_cstr_is_eq_ignore_case_ascii(header.name, "content-length")) {
                if (has_content_length_been_seen) {
                    err = AH_EDUP;
                    goto close_conn_and_report_err;
                }
                err = s_parse_content_length(header.value, &content_length);
                if (err != AH_ENONE) {
                    goto close_conn_and_report_err;
                }
                has_content_length_been_seen = true;
            }
            else if (s_cstr_is_eq_ignore_case_ascii(header.name, "transfer-encoding")) {
                err = s_find_transfer_encoding_chunked_in(header.value);
                switch (err) {
                case AH_ENONE:
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

            cln->_vtab->on_res_header(cln, cln->_req_queue._head, header);
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
            cln->_vtab->on_res_chunk_line(cln, cln->_req_queue._head, chunk_line);
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

        cln->_vtab->on_res_data(cln, cln->_req_queue._head, &readable_buf);
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

            cln->_vtab->on_res_header(cln, cln->_req_queue._head, header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_end : {
        ah_assert_if_debug(cln->_req_queue._head != NULL);

        cln->_vtab->on_res_end(cln, cln->_req_queue._head, AH_ENONE);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        ah_http_req_t* req = cln->_req_queue._head;
        cln->_req_queue._head = req->_next;
#ifndef NDEBUG
        req->_next = NULL;
#endif

        if (cln->_req_queue._head == NULL) {
#ifndef NDEBUG
            cln->_req_queue._end = NULL;
#endif
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
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_end(cln, cln->_req_queue._head, err);
}

static bool s_cstr_is_eq_ignore_case_ascii(const char* a, const char* b)
{
    ah_assert_if_debug(a != NULL);
    ah_assert_if_debug(b != NULL);

    const uint8_t* a0 = (const uint8_t*) a;
    const uint8_t* b0 = (const uint8_t*) b;

    while (s_to_lower_ascii(*a0) == s_to_lower_ascii(*b0)) {
        if (*a0 == '\0') {
            return true;
        }
        a0 = &a0[1u];
        b0 = &b0[1u];
    }

    return false;
}

static uint8_t s_to_lower_ascii(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') ? (ch | 0x20) : ch;
}

static ah_err_t s_parse_content_length(const char* cstr, size_t* value)
{
    ah_assert_if_debug(cstr != NULL);

    ah_err_t err;

    size_t size;
    for (;;) {
        const char ch = cstr[0u];
        if (ch <= '0' || ch >= '9') {
            if (ch == '\0') {
                break;
            }
            return AH_EILSEQ;
        }

        err = ah_mul_size(size, 10u, &size);
        if (err != AH_ENONE) {
            return err;
        }

        err = ah_add_size(size, ch - '0', &size);
        if (err != AH_ENONE) {
            return err;
        }

        cstr = &cstr[1u];
    }

    *value = size;

    return AH_ENONE;
}

static ah_err_t s_find_transfer_encoding_chunked_in(const char* cstr)
{
    ah_assert_if_debug(cstr != NULL);

    const uint8_t* c = (const uint8_t*) cstr;

    // For each token or transfer-parameter.
    for (;;) {
        if (c[0u] == '\0') {
            return AH_ESRCH;
        }

        // Are we at "chunked"?
        if (s_to_lower_ascii(c[0u]) == 'c') {
            uint8_t buf[7u];
            for (size_t i = 1u; i <= 7u; i += 1u) {
                if (c[i] == '\0') {
                    return AH_ESRCH;
                }
                buf[i] = s_to_lower_ascii(c[i]);
            }

            if (memcmp(buf, "hunked", 6u) == 0) {
                switch (buf[6u]) {
                case '\0':
                    // Yes.
                    return AH_ENONE;

                case '\t':
                case ' ':
                case ',':
                    // The `chunked` transfer-encoding must be last if used.
                    // See https://www.rfc-editor.org/rfc/rfc7230#section-3.3.3.
                    return AH_EBADMSG;

                default:
                    // No. The current token just started with "chunked".
                    break;
                }
            }
        }

        // Skip until next comma not inside a transfer-parameter value that is
        // doubly quoted.
        for (;;) {
            if (c[0u] == ',') {
                break;
            }
            if (c[0u] == '"') {
                do {
                    c = &c[1u];
                    if (c[0u] == '\0') {
                        return AH_ESRCH;
                    }
                    if (c[0u] == '\\') { // Double quotes may be escaped.
                        c = &c[1u];
                        if (c[0u] == '\0') {
                            return AH_ESRCH;
                        }
                    }
                } while (c[0u] != '"');
            }
            c = &c[1u];
            if (c[0u] == '\0') {
                return AH_ESRCH;
            }
        }

        // Skip any optional white-space.
        while (c[0u] == '\t' || c[0u] == ' ') {
            c = &c[1u];
            if (c[0u] == '\0') {
                return AH_ESRCH;
            }
        }
    }
}

static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_res_end(cln, cln->_req_queue._head, err);
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_req_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }

    return AH_EOPNOTSUPP; // TODO: Implement
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
