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

static void s_on_read_alloc(ah_tcp_conn_t* conn, ah_buf_t* buf);
static void s_on_read_data(ah_tcp_conn_t* conn, const ah_buf_t* buf, size_t nread);
static void s_on_read_err(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_write_done(ah_tcp_conn_t* conn, ah_err_t err);

static void s_read_chunk_data(ah_http_client_t* cln, const ah_buf_t* buf, size_t nread);
static ah_err_t s_read_chunk_start(ah_http_client_t* cln, ah_i_http_reader_t r);
static void s_read_data(ah_http_client_t* cln, const ah_buf_t* buf, size_t nread);
static ah_err_t s_read_headers(ah_http_client_t* cln, ah_i_http_reader_t r);
static ah_err_t s_read_res_line(ah_http_client_t* cln, ah_i_http_reader_t r);
static ah_err_t s_read_trailer(ah_http_client_t* cln, ah_i_http_reader_t r);

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
    ah_assert_if_debug(vtab->on_res_alloc_head != NULL);
    ah_assert_if_debug(vtab->on_res_alloc_more != NULL);
    ah_assert_if_debug(vtab->on_res_line != NULL);
    ah_assert_if_debug(vtab->on_res_headers != NULL);
    ah_assert_if_debug(vtab->on_res_chunk != NULL);
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

    cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING;
    cln->_istate = AH_I_HTTP_CLIENT_OSTATE_READY;

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

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING:
        err = AH_ESTATE;
        goto close_conn_and_report_err;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START:
        cln->_ires = NULL;

        cln->_vtab->on_res_alloc_head(cln, &cln->_ires, buf);

        if (ah_buf_is_empty(buf)) {
            return;
        }
        if (cln->_ires == NULL) {
            err = AH_ENOBUFS;
            goto close_conn_and_report_err;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT;
        cln->_i_non_data_buf_rd = *buf;
        cln->_i_non_data_buf_wr = *buf;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK_START:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        if (ah_buf_is_empty(&cln->_i_non_data_buf_wr)) {
            err = AH_EOVERFLOW;
            goto close_conn_and_report_err;
        }
        *buf = cln->_i_non_data_buf_wr;
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
        cln->_vtab->on_res_alloc_more(cln, buf);
        return;

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

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START:
        err = AH_ESTATE;
        goto close_conn_and_report_err;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
        err = s_read_res_line(cln, ah_i_http_reader_from(buf, nread));
        break;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        err = s_read_headers(cln, ah_i_http_reader_from(buf, nread));
        break;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
        s_read_data(cln, buf, nread);
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK_START:
        err = s_read_chunk_start(cln, ah_i_http_reader_from(buf, nread));
        break;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK_DATA:
        s_read_chunk_data(cln, buf, nread);
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        err = s_read_trailer(cln, ah_i_http_reader_from(buf, nread));
        break;

    default:
        ah_unreachable();
    }

    if (err == AH_ENONE) {
        return;
    }

    /*
    ah_i_http_reader_t r = ah_i_http_reader_from(buf, nread);


    ah_http_chunk_t chunk;
    ah_http_data_t data;
    ah_buf_t data_buf;
    bool is_chunked;

    switch (cln->_istate) {
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING:
    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START:
        err = AH_ESTATE;
        goto close_conn_and_report_err;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_CONT:
        ah_assert_if_debug(ah_buf_get_base_const(buf) == ah_buf_get_base(&cln->_i_non_data_buf_wr));

        err = ah_i_http_skip_until_after_line_end(&cln->_i_non_data_buf_wr, NULL);
        switch (err) {
        case AH_ENONE:
            break;

        case AH_EAGAIN:
            return;

        case AH_EILSEQ:
            goto close_conn_and_report_err;

        default:
            ah_unreachable();
        }

        if (!ah_i_http_parse_stat_line(&cln->_i_non_data_buf_rd, NULL, &cln->_ires->stat_line)) {
            err = AH_EILSEQ;
            goto close_conn_and_report_err;
        }

        cln->_vtab->on_res_line(cln, cln->_ires);

        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS;
        goto expect_headers;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS:
        ah_assert_if_debug(ah_buf_get_base_const(buf) == ah_buf_get_base(&cln->_i_non_data_buf_wr));

    expect_headers:
        err = ah_i_http_skip_until_after_headers_end(&cln->_i_non_data_buf_wr, NULL);
        switch (err) {
        case AH_ENONE:
            break;

        case AH_EAGAIN:
            return;

        case AH_EILSEQ:
            goto close_conn_and_report_err;

        default:
            ah_unreachable();
        }

        if (!ah_i_http_parse_headers(&cln->_i_non_data_buf_rd, NULL, &cln->_ires->headers)) {
            err = AH_EILSEQ;
            goto close_conn_and_report_err;
        }

        cln->_vtab->on_res_headers(cln, cln->_ires);

        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        err = ah_i_http_hmap_is_transfer_encoding_chunked(&cln->_ires->headers, &is_chunked);
        if (err != AH_ENONE) {
            goto close_conn_and_report_err;
        }

        if (is_chunked) {
            err = ah_http_hmap_get_value(&cln->_ires->headers, ah_str_from_cstr("content-length"), NULL);
            if (err != AH_ESRCH) {
                err = AH_EBADMSG;
                goto close_conn_and_report_err;
            }
            cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK_START;
            goto expect_chunk;
        }

        err = ah_i_http_hmap_get_content_length(&cln->_ires->headers, &cln->_i_n_bytes_expected);
        if (err != AH_ENONE) {
            goto close_conn_and_report_err;
        }

        if (cln->_i_n_bytes_expected == 0u) {
            cln->_n_pending_responses -= 1u;
            if (cln->_n_pending_responses == 0u) {
                cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING;
            }
            else {
                cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START;
            }
            return;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA;

        if (ah_buf_is_empty(&cln->_i_non_data_buf_rd)) {
            return;
        }
        data_buf = cln->_i_non_data_buf_rd;
        goto expect_data;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK_START:
        ah_assert_if_debug(ah_buf_get_base_const(buf) == ah_buf_get_base(&cln->_i_non_data_buf_wr));

    expect_chunk:
        err = ah_i_http_skip_until_after_line_end(&cln->_i_non_data_buf_wr, NULL);
        switch (err) {
        case AH_ENONE:
            break;

        case AH_EAGAIN:
            return;

        case AH_EILSEQ:
            goto close_conn_and_report_err;

        default:
            ah_unreachable();
        }

        err = ah_i_http_parse_chunk(&cln->_i_non_data_buf_rd, NULL, &chunk);
        if (err != AH_ENONE) {
            goto close_conn_and_report_err;
        }
        cln->_i_n_bytes_expected = chunk.size;
        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA;

        if (ah_buf_is_empty(&cln->_i_non_data_buf_rd)) {
            return;
        }
        data_buf = cln->_i_non_data_buf_rd;
        goto expect_data;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA:
        data_buf = *buf;

    expect_data:
        cln->_vtab->on_res_data(cln, cln->_ires, NULL); // TODO.
        return;

    case AH_I_HTTP_CLIENT_ISTATE_EXPECTING_TRAILER:
        return;

    default:
        ah_unreachable();
    }
*/
close_conn_and_report_err:
    cln->_trans_vtab->conn_close(conn);
    cln->_vtab->on_res_end(cln, NULL, err);

}

static ah_err_t s_read_res_line(ah_http_client_t* cln, ah_i_http_reader_t r)
{
    ah_err_t err;

    err = ah_i_http_skip_until_after_line_end(&cln->_i_non_data_buf_wr, NULL);
    if (err != AH_ENONE) {
        return err != AH_EAGAIN ? err : AH_ENONE;
    }

    err = ah_i_http_parse_stat_line(&cln->_i_non_data_buf_rd, NULL, &cln->_ires->stat_line);
    if (err != AH_ENONE) {
        return err;
    }

    cln->_vtab->on_res_line(cln, cln->_ires);

    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
        return AH_ENONE;
    }

    cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_HEADERS;
    return s_read_headers(cln, r);
}

static ah_err_t s_read_headers(ah_http_client_t* cln, ah_i_http_reader_t r)
{
    ah_err_t err;

    err = ah_i_http_skip_until_after_headers_end(&cln->_i_non_data_buf_wr, NULL);
    if (err != AH_ENONE) {
        return err != AH_EAGAIN ? err : AH_ENONE;
    }

    err = ah_i_http_parse_headers(&cln->_i_non_data_buf_rd, NULL, &cln->_ires->headers);
    if (err != AH_ENONE) {
        return err;
    }

    cln->_vtab->on_res_headers(cln, cln->_ires);

    if (!ah_tcp_conn_is_readable(&cln->_conn)) {
        return AH_ENONE;
    }

    bool is_chunked;
    err = ah_i_http_hmap_is_transfer_encoding_chunked(&cln->_ires->headers, &is_chunked);
    if (err != AH_ENONE) {
        return err;
    }

    if (is_chunked) {
        err = ah_http_hmap_get_value(&cln->_ires->headers, ah_str_from_cstr("content-length"), NULL);
        if (err != AH_ESRCH) {
            return AH_EBADMSG;
        }

        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_CHUNK_START;
        return s_read_chunk_start(cln, r);
    }

    err = ah_i_http_hmap_get_content_length(&cln->_ires->headers, &cln->_i_n_bytes_expected);
    if (err != AH_ENONE) {
        return err;
    }

    if (cln->_i_n_bytes_expected == 0u) {
        cln->_n_pending_responses -= 1u;
        cln->_istate = cln->_n_pending_responses == 0u
            ? AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING
            : AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START;
        return AH_ENONE;
    }

    cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_DATA;

    if (ah_i_http_reader_is_empty(&r)) {
        return AH_ENONE;
    }

    return ah
}

static void s_read_data(ah_http_client_t* cln, const ah_buf_t* buf, size_t nread)
{

}

static void s_read_chunk_data(ah_http_client_t* cln, const ah_buf_t* buf, size_t nread)
{

}

static ah_err_t s_read_chunk_start(ah_http_client_t* cln, ah_i_http_reader_t r)
{

}

static ah_err_t s_read_trailer(ah_http_client_t* cln, ah_i_http_reader_t r)
{

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
        ah_assert_if_debug(cln->_istate == AH_I_HTTP_CLIENT_ISTATE_EXPECTING_NOTHING);
        cln->_istate = AH_I_HTTP_CLIENT_ISTATE_EXPECTING_RES_LINE_START;
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
