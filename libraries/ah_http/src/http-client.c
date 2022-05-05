// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"

#include <ah/err.h>
#include <ah/math.h>

static const ah_http_ires_err_t s_ires_err_alloc_failed = {
    "memory allocation failed",
    AH_HTTP_IRES_ERR_ALLOC_FAILED,
    AH_ENOMEM,
};
static const ah_http_ires_err_t s_ires_err_buffer_overflow = {
    "response buffer overflowed (should be impossible)",
    AH_HTTP_IRES_ERR_BUFFER_OVERFLOW,
    AH_EOVERFLOW,
};
static const ah_http_ires_err_t s_ires_err_head_too_large = {
    "status line and headers too large for allocated head buffer",
    AH_HTTP_IRES_ERR_HEAD_TOO_LARGE,
    AH_ENOBUFS,
};
static const ah_http_ires_err_t s_ires_err_invalid_headers = {
    "invalid headers",
    AH_HTTP_IRES_ERR_INVALID_HEADERS,
    AH_EILSEQ,
};
static const ah_http_ires_err_t s_ires_err_invalid_stat_line = {
    "invalid status line",
    AH_HTTP_IRES_ERR_INVALID_STAT_LINE,
    AH_EILSEQ,
};
static const ah_http_ires_err_t s_ires_err_trailer_too_large = {
    "trailing headers too large for allocated trailer buffer",
    AH_HTTP_IRES_ERR_TRAILER_TOO_LARGE,
    AH_ENOBUFS,
};

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static bool s_is_chunked(ah_str_t csv);
static ah_err_t s_str_dec_to_size(ah_str_t str, size_t* size);

static ah_http_client_t* s_upcast_to_client(ah_tcp_conn_t* conn);

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_tcp_trans_t trans, const ah_http_client_vtab_t* vtab)
{
    if (cln == NULL || trans._vtab == NULL || trans._loop == NULL || vtab == NULL) {
        return AH_EINVAL;
    }

    (void) s_ires_err_trailer_too_large;

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
    ah_assert_if_debug(vtab->on_res_alloc_head != NULL);
    ah_assert_if_debug(vtab->on_res_alloc_more != NULL);
    ah_assert_if_debug(vtab->on_res_line != NULL);
    ah_assert_if_debug(vtab->on_res_headers != NULL);
    ah_assert_if_debug(vtab->on_res_chunk != NULL);
    ah_assert_if_debug(vtab->on_res_data != NULL);
    ah_assert_if_debug(vtab->on_res_err != NULL);
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

    cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING;
    cln->_ostate = AH_I_HTTP_CLIENT_OSTATE_READY;

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

static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_connect(cln, err);
}

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    const ah_http_ires_err_t* ires_err;

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING:
        ires_err = NULL; // TODO.
        goto close_conn_and_report_ires_err;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START:
        cln->_ires = NULL;

        cln->_vtab->on_res_alloc_head(cln, &cln->_ires, buf);

        if (cln->_ires == NULL) {
            ires_err = &s_ires_err_alloc_failed;
            goto close_conn_and_report_ires_err;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT;
        cln->_ihead_rd = *buf;
        cln->_ihead_wr = cln->_ihead_rd;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        if (ah_buf_is_empty(&cln->_ihead_wr)) {
            ires_err = &s_ires_err_head_too_large;
            goto close_conn_and_report_ires_err;
        }
        *buf = cln->_ihead_wr;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        cln->_vtab->on_res_alloc_more(cln, buf);
        return;

    default:
        ah_unreachable();
    }

close_conn_and_report_ires_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_err(cln, NULL, ires_err);
}

static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    ah_err_t err;
    const ah_http_ires_err_t* ires_err;

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
        if (!ah_i_http_buf_has_crlf(buf)) {
            err = ah_buf_shrinkl(&cln->_ihead_wr, nread);
            if (err != AH_ENONE) {
                ires_err = &s_ires_err_buffer_overflow;
                goto close_conn_and_report_ires_err;
            }
            return;
        }
        if (!ah_i_http_parse_stat_line(&cln->_ihead_rd, &cln->_ires->stat_line)) {
            ires_err = &s_ires_err_invalid_stat_line;
            goto close_conn_and_report_ires_err;
        }

        cln->_vtab->on_res_line(cln, cln->_ires);

        if (ah_tcp_conn_is_closed(&cln->_conn)) {
            return;
        }

        cln->_ostate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS;
        // fallthrough

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        if (!ah_i_http_buf_has_crlfx2(buf)) {
            err = ah_buf_shrinkl(&cln->_ihead_wr, nread);
            if (err != AH_ENONE) {
                ires_err = &s_ires_err_buffer_overflow;
                goto close_conn_and_report_ires_err;
            }
            return;
        }
        if (!ah_i_http_parse_headers(&cln->_ihead_rd, &cln->_ires->headers)) {
            ires_err = &s_ires_err_invalid_headers;
            goto close_conn_and_report_ires_err;
        }

        cln->_vtab->on_res_headers(cln, cln->_ires);

        if (ah_tcp_conn_is_closed(&cln->_conn)) {
            return;
        }

        if (ah_http_hmap_has_csv(&cln->_ires->headers, ah_str_from_cstr("transfer-encoding"), s_is_chunked)) {
            cln->_ostate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK;
            return;
        }

        bool has_next;
        const ah_str_t* content_length = ah_http_hmap_get_value(&cln->_ires->headers,
            ah_str_from_cstr("content-length"), &has_next);

        if (content_length == NULL) {
            if (has_next) {
                ires_err = NULL; // TODO.
                goto close_conn_and_report_ires_err;
            }
            cln->_i_n_bytes_expected = 0u;
        }
        else {
            err = s_str_dec_to_size(*content_length, &cln->_i_n_bytes_expected);
            switch (err) {
            case AH_ENONE:
                cln->_ostate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA;
                break;

            case AH_EILSEQ:
                ires_err = NULL; // TODO.
                goto close_conn_and_report_ires_err;

            case AH_ERANGE:
                ires_err = NULL; // TODO.
                goto close_conn_and_report_ires_err;

            default:
                ah_unreachable();
            }
        }

        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK:
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        return;

    default:
        ah_unreachable();
    }

close_conn_and_report_ires_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_err(cln, NULL, ires_err);
}

static bool s_is_chunked(ah_str_t csv)
{
    return ah_str_eq_ignore_case_ascii(csv, ah_str_from_cstr("chunked"));
}

static ah_err_t s_str_dec_to_size(ah_str_t str, size_t* size)
{
    ah_err_t err;
    size_t size0 = 0u;

    const char* off = ah_str_get_ptr(&str);
    const char* const end = &off[ah_str_get_len(&str)];

    if (off == end) {
        return AH_EILSEQ;
    }

    for (;;) {
        const char ch = off[0u];
        if (ch <= '0' || ch >= '9') {
            return AH_EILSEQ;
        }

        err = ah_mul_size(size0, 10u, &size0);
        if (err != AH_ENONE) {
            return err;
        }

        err = ah_add_size(size0, ch - '0', &size0);
        if (err != AH_ENONE) {
            return err;
        }

        if (off == end) {
            break;
        }

        off = &off[1u];
    }

    *size = size0;

    return AH_ENONE;
}

static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);

    if (err == AH_ENOBUFS) {
        cln->_vtab->on_res_err(cln, NULL, &s_ires_err_alloc_failed);
        return;
    }

    ah_http_ires_err_t ires_err = { "unexpected transport error", AH_HTTP_IRES_ERR_TRANSPORT_ERROR, err };
    cln->_vtab->on_res_err(cln, NULL, &ires_err);
}

ah_extern ah_err_t ah_http_client_request(ah_http_client_t* cln, const ah_http_oreq_t* req)
{
    if (cln == NULL || req == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = ah_tcp_conn_read_start(&cln->_conn);

    (void) err;
    (void) cln;
    (void) req;
    return AH_EOPNOTSUPP; // TODO: Implement.
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

static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = s_upcast_to_client(conn);
    cln->_vtab->on_close(cln, err);
}
