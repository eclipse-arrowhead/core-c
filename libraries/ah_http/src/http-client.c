// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-hmap.h"
#include "http-parser.h"

#include <ah/err.h>
#include <ah/math.h>

// Input (response) states.
#define S_I_STATE_EXPECTING_NOTHING              0u
#define S_I_STATE_EXPECTING_RESPONSE             1u
#define S_I_STATE_EXPECTING_STAT_LINE            2u
#define S_I_STATE_EXPECTING_HEADERS_HEADER_NAME  3u
#define S_I_STATE_EXPECTING_HEADERS_HEADER_VALUE 4u
#define S_I_STATE_EXPECTING_HEADERS_HEADER_CRLF  5u
#define S_I_STATE_EXPECTING_HEADERS_CRLF         6u
#define S_I_STATE_EXPECTING_DATA                 7u
#define S_I_STATE_EXPECTING_CHUNK_LINE           8u
#define S_I_STATE_EXPECTING_CHUNK_DATA           9u
#define S_I_STATE_EXPECTING_TRAILER_HEADER_NAME  10u
#define S_I_STATE_EXPECTING_TRAILER_HEADER_VALUE 11u
#define S_I_STATE_EXPECTING_TRAILER_HEADER_CRLF  12u
#define S_I_STATE_EXPECTING_TRAILER_CRLF         13u

// Output (request) states.
#define S_O_STATE_READY        0u
#define S_O_STATE_SENDING_HEAD 1u
#define S_O_STATE_SENDING_BODY 2u

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static void s_read_chunk_data(ah_http_client_t* cln, const ah_buf_t* buf, size_t nread);
static ah_err_t s_read_chunk_start(ah_http_client_t* cln, ah_i_http_parser_t r);
static void s_read_data(ah_http_client_t* cln, const ah_buf_t* buf, size_t nread);
static ah_err_t s_read_headers(ah_http_client_t* cln, ah_i_http_parser_t r);
static ah_err_t s_read_res_line(ah_http_client_t* cln, ah_i_http_parser_t r);
static ah_err_t s_read_trailer(ah_http_client_t* cln, ah_i_http_parser_t r);

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
    ah_assert_if_debug(vtab->on_res_headers != NULL);
    ah_assert_if_debug(vtab->on_res_chunk_line != NULL);
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

    cln->_i_state = S_I_STATE_EXPECTING_NOTHING;
    cln->_i_state = S_O_STATE_READY;

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

    switch (cln->_i_state) {
    case S_I_STATE_EXPECTING_NOTHING: {
        err = AH_ESTATE;
        goto close_conn_and_report_err;
    }

    case S_I_STATE_EXPECTING_RESPONSE: {
        ah_assert_if_debug(cln->_i_hmap_size_log2 <= 8u);

        const size_t ires_size = sizeof(ah_http_ires_t);
        const size_t hmap_size = sizeof(struct ah_i_http_hmap_header) << cln->_i_hmap_size_log2;
        const size_t preamble_size = ires_size + hmap_size;

        cln->_vtab->on_res_alloc(cln, buf, preamble_size);
        if (ah_buf_get_size(buf) <= preamble_size) {
            err = AH_ENOBUFS;
            goto close_conn_and_report_err;
        }

        uint8_t* base = ah_buf_get_base(buf);

        cln->_i_res = (void*) &base[0u];
        ah_i_http_hmap_init(&cln->_i_res->headers, (void*) &base[ires_size], 1u << cln->_i_hmap_size_log2);
        ah_i_http_parser_init(&cln->_i_parser, &base[preamble_size], ah_buf_get_size(buf) - preamble_size);
        return;
    }

    case S_I_STATE_EXPECTING_STAT_LINE:
    case S_I_STATE_EXPECTING_HEADERS_HEADER_NAME:
    case S_I_STATE_EXPECTING_HEADERS_HEADER_VALUE:
    case S_I_STATE_EXPECTING_HEADERS_HEADER_CRLF:
    case S_I_STATE_EXPECTING_HEADERS_CRLF:
    case S_I_STATE_EXPECTING_CHUNK_LINE:
    case S_I_STATE_EXPECTING_TRAILER_HEADER_NAME:
    case S_I_STATE_EXPECTING_TRAILER_HEADER_VALUE:
    case S_I_STATE_EXPECTING_TRAILER_HEADER_CRLF:
    case S_I_STATE_EXPECTING_TRAILER_CRLF: {
        if (ah_i_http_parser_is_writable(&cln->_i_parser)) {
            ah_i_http_parser_get_writable_buf(&cln->_i_parser, buf);
        }
        else {
            const size_t min_size = ah_i_http_parser_not_yet_parsed_size(&cln->_i_parser);

            cln->_vtab->on_res_alloc(cln, buf, min_size);
            if (ah_buf_get_size(buf) <= min_size) {
                err = AH_ENOBUFS;
                goto close_conn_and_report_err;
            }

            err = ah_i_http_parser_migrate_to(&cln->_i_parser, buf);
            if (err != AH_ENONE) {
                goto close_conn_and_report_err;
            }
        }
        return;
    }

    case S_I_STATE_EXPECTING_DATA:
    case S_I_STATE_EXPECTING_CHUNK_DATA: {
        cln->_vtab->on_res_alloc(cln, buf, 0u);
        return;
    }

    default:
        ah_unreachable();
    }

close_conn_and_report_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_end(cln, NULL, err);
}

static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    ah_err_t err;

    err = ah_i_http_parser_set_readable_size(&cln->_i_parser, buf, nread);
    if (err != AH_ENONE) {
        goto close_conn_and_report_err;
    }

    switch (cln->_i_state) {
    expecting_nothing:
    case S_I_STATE_EXPECTING_NOTHING: {
        if (ah_i_http_parser_not_yet_parsed_size(&cln->_i_parser) != 0) {
            err = AH_ESTATE;
            goto close_conn_and_report_err;
        }
        return;
    }

    expecting_response:
    case S_I_STATE_EXPECTING_RESPONSE: {
        ah_assert_if_debug(cln->_n_pending_responses > 0u);
        cln->_n_pending_responses -= 1u;

        ah_i_http_hmap_reset(&cln->_i_res->headers);

        cln->_i_state = S_I_STATE_EXPECTING_HEADERS_HEADER_NAME;
        goto expecting_stat_line;
    }

    expecting_stat_line:
    case S_I_STATE_EXPECTING_STAT_LINE: {
        err = ah_i_http_parse_res_line(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_vtab->on_res_stat_line(cln, cln->_i_res);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_i_state = S_I_STATE_EXPECTING_HEADERS_HEADER_NAME;
        goto expecting_headers_header_name;
    }

    expecting_headers_header_name:
    case S_I_STATE_EXPECTING_HEADERS_HEADER_NAME: {
        err = ah_i_http_parse_header_name(&cln->_i_parser);
        if (err != AH_ENONE) {
            if (err == AH_ESRCH) {
                cln->_i_state = S_I_STATE_EXPECTING_HEADERS_CRLF;
                goto expecting_headers_crlf;
            }
            break;
        }

        cln->_i_state = S_I_STATE_EXPECTING_HEADERS_HEADER_VALUE;
        goto expecting_headers_header_value;
    }

    expecting_headers_header_value:
    case S_I_STATE_EXPECTING_HEADERS_HEADER_VALUE: {
        err = ah_i_http_parse_header_value(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_i_state = S_I_STATE_EXPECTING_HEADERS_HEADER_CRLF;
        goto expecting_headers_header_crlf;
    }

    expecting_headers_header_crlf:
    case S_I_STATE_EXPECTING_HEADERS_HEADER_CRLF: {
        err = ah_i_http_skip_crlf(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_i_state = S_I_STATE_EXPECTING_HEADERS_HEADER_NAME;
        goto expecting_headers_header_name;
    }

    expecting_headers_crlf:
    case S_I_STATE_EXPECTING_HEADERS_CRLF: {
        err = ah_i_http_skip_crlf(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_vtab->on_res_headers(cln, cln->_i_res);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        bool is_chunked;
        err = ah_i_http_hmap_is_transfer_encoding_chunked(&cln->_i_res->headers, &is_chunked);
        if (err != AH_ENONE) {
            goto close_conn_and_report_err;
        }

        if (is_chunked) {
            err = ah_http_hmap_get_value(&cln->_i_res->headers, ah_str_from_cstr("content-length"), NULL);
            if (err != AH_ESRCH) {
                err = AH_EBADMSG;
                goto close_conn_and_report_err;
            }
            cln->_i_state = S_I_STATE_EXPECTING_CHUNK_LINE;
            goto expecting_chunk_line;
        }

        err = ah_i_http_hmap_get_content_length(&cln->_i_res->headers, &cln->_i_n_bytes_expected);
        if (err != AH_ENONE) {
            goto close_conn_and_report_err;
        }

        if (cln->_i_n_bytes_expected == 0u) {
            goto response_end;
        }

        cln->_i_state = S_I_STATE_EXPECTING_DATA;
        goto expecting_data;
    }

    expecting_chunk_line:
    case S_I_STATE_EXPECTING_CHUNK_LINE: {
        ah_http_chunk_line_t chunk_line;

        err = ah_i_http_parse_chunk_line(&cln->_i_parser, &chunk_line);
        if (err != AH_ENONE) {
            break;
        }

        if (cln->_vtab->on_res_chunk_line != NULL) {
            cln->_vtab->on_res_chunk_line(cln, cln->_i_res, &chunk_line);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }

        if (chunk_line.size == 0u) {
            ah_assert_if_debug(cln->_i_n_bytes_expected == 0u);
            cln->_i_state = S_I_STATE_EXPECTING_TRAILER_HEADER_NAME;
            goto expecting_trailer_header_name;
        }

        cln->_i_n_bytes_expected = chunk_line.size;
        cln->_i_state = S_I_STATE_EXPECTING_CHUNK_DATA;
        goto expecting_chunk_data;
    }

    expecting_data:
    expecting_chunk_data:
    case S_I_STATE_EXPECTING_DATA:
    case S_I_STATE_EXPECTING_CHUNK_DATA: {
        ah_buf_t readable_buf;
        ah_i_http_parser_get_readable_buf(&cln->_i_parser, &readable_buf);

        size_t readable_buf_size = ah_buf_get_size(&readable_buf);
        if (cln->_i_n_bytes_expected < readable_buf_size) {
            err = ah_buf_init(&readable_buf, ah_buf_get_base(&readable_buf), cln->_i_n_bytes_expected);
            if (err != AH_ENONE) {
                goto close_conn_and_report_err;
            }
            cln->_i_n_bytes_expected = 0u;
        }
        else {
            cln->_i_n_bytes_expected -= readable_buf_size;
        }

        cln->_vtab->on_res_data(cln, cln->_i_res, &readable_buf);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        if (cln->_i_n_bytes_expected == 0u) {
            if (cln->_i_state == S_I_STATE_EXPECTING_DATA) {
                goto response_end;
            }
            cln->_i_state = S_I_STATE_EXPECTING_CHUNK_LINE;
            goto expecting_chunk_line;
        }

        return;
    }

    expecting_trailer_header_name:
    case S_I_STATE_EXPECTING_TRAILER_HEADER_NAME: {
        err = ah_i_http_parse_header_name(&cln->_i_parser);
        if (err != AH_ENONE) {
            if (err == AH_ESRCH) {
                cln->_i_state = S_I_STATE_EXPECTING_TRAILER_CRLF;
                goto expecting_trailer_crlf;
            }
            break;
        }

        cln->_i_state = S_I_STATE_EXPECTING_TRAILER_HEADER_VALUE;
        goto expecting_trailer_header_value;
    }

    expecting_trailer_header_value:
    case S_I_STATE_EXPECTING_TRAILER_HEADER_VALUE: {
        err = ah_i_http_parse_header_value(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_i_state = S_I_STATE_EXPECTING_TRAILER_HEADER_CRLF;
        goto expecting_trailer_header_crlf;
    }

    expecting_trailer_header_crlf:
    case S_I_STATE_EXPECTING_TRAILER_HEADER_CRLF: {
        err = ah_i_http_skip_crlf(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_i_state = S_I_STATE_EXPECTING_TRAILER_HEADER_NAME;
        goto expecting_trailer_header_name;
    }

    expecting_trailer_crlf:
    case S_I_STATE_EXPECTING_TRAILER_CRLF: {
        err = ah_i_http_skip_crlf(&cln->_i_parser);
        if (err != AH_ENONE) {
            break;
        }

        cln->_vtab->on_res_headers(cln, cln->_i_res);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        goto response_end;
    }

    default:
        ah_unreachable();
    }

    if (err == AH_ENONE || err == AH_EAGAIN) {
        return;
    }

response_end:
    cln->_vtab->on_res_end(cln, cln->_i_res, AH_ENONE);
    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
        return;
    }

    if (cln->_n_pending_responses == 0u) {
        cln->_i_state = S_I_STATE_EXPECTING_NOTHING;
        goto expecting_nothing;
    }

    cln->_i_state = S_I_STATE_EXPECTING_RESPONSE;
    goto expecting_response;

close_conn_and_report_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_end(cln, NULL, err);
}

static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_res_end(cln, NULL, err);
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }

    // TODO: Send message.

    if (cln->_n_pending_responses == 0u) {
        ah_assert_if_debug(cln->_i_state == S_I_STATE_EXPECTING_NOTHING);
        cln->_i_state = S_I_STATE_EXPECTING_RESPONSE;
    }
    cln->_n_pending_responses += 1u; // TODO: Check overflow.

    return AH_EOPNOTSUPP; // TODO: Change to AH_ENONE once implemented.
}

static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    // TODO: Check state, report if sending is complete or failed.
    (void) cln;
    (void) err;
}

ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return cln->_trans_vtab->conn_close(&cln->_conn);
}
