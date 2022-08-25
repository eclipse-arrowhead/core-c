// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include "http-parser.h"
#include "http-utils.h"
#include "http-writer.h"

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

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_read(ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_on_write(ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err);

static void s_finalize_and_discard_out_queue_head(ah_http_client_t* cln, ah_err_t err);
static void s_write_first_head_in_out_queue(ah_http_client_t* cln);

static const ah_tcp_conn_cbs_t s_cbs = {
    .on_open = s_on_open,
    .on_connect = s_on_connect,
    .on_read = s_on_read,
    .on_write = s_on_write,
    .on_close = s_on_close,
};

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_loop_t* loop, ah_tcp_trans_t trans, const ah_http_client_cbs_t* cbs)
{
    if (cln == NULL || cbs == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_open == NULL || cbs->on_connect == NULL || cbs->on_send == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_recv_line == NULL || cbs->on_recv_header == NULL || cbs->on_recv_data == NULL || cbs->on_recv_end == NULL) {
        return AH_EINVAL;
    }
    if (cbs->on_close == NULL) {
        return AH_EINVAL;
    }

    *cln = (ah_http_client_t) {
        ._cbs = cbs,
        ._in_state = S_IN_STATE_INIT,
        ._is_local = true,
    };

    return ah_tcp_conn_init(&cln->_conn, loop, trans, &s_cbs);
}

ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_open(&cln->_conn, laddr);
}

static void s_on_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);
    cln->_cbs->on_open(cln, err);
}

ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    ah_err_t err = ah_tcp_conn_connect(&cln->_conn, raddr);
    if (err == AH_ENONE) {
        cln->_raddr = raddr;
    }
    return err;
}

static void s_on_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    cln->_cbs->on_connect(cln, err);
    if (err != AH_ENONE || ah_tcp_conn_is_closed(conn)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return;

handle_err:
    cln->_cbs->on_recv_end(cln, err);
}

static void s_on_read(ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    if (err != AH_ENONE) {
        goto report_err_and_close_conn;
    }

    switch (cln->_in_state) {
    case S_IN_STATE_INIT: {
        if (cln->_is_local && cln->_in_n_expected_responses == 0u) {
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
        if (cln->_is_local) {
            err = ah_i_http_parse_stat_line(&in->rw, &line, &version);
        }
        else {
            err = ah_i_http_parse_req_line(&in->rw, &line, &version);
        }
        if (err != AH_ENONE) {
            goto handle_parse_err;
        }

        if (version.major != 1u) {
            err = AH_EPROTONOSUPPORT;
            goto report_err_and_close_conn;
        }

        cln->_cbs->on_recv_line(cln, line, version);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        cln->_is_keeping_connection_open = version.minor != 0u;

        cln->_in_state = S_IN_STATE_HEADERS;
        goto state_headers;
    }

    state_headers:
    case S_IN_STATE_HEADERS: {
        bool has_connection_close_been_seen = false;
        bool has_content_length_been_seen = false;
        bool has_transfer_encoding_chunked_been_seen = false;
        size_t content_length = 0u;

        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&in->rw, &header);
            if (err != AH_ENONE) {
                goto handle_parse_err;
            }

            if (header.name == NULL) {
                if (cln->_cbs->on_recv_headers != NULL) {
                    cln->_cbs->on_recv_headers(cln);
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
                err = ah_i_http_header_value_find_csv(header.value, "chunked", &rest);
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
                if (ah_i_http_header_value_find_csv(header.value, "close", NULL) == AH_ENONE) {
                    cln->_is_keeping_connection_open = false;
                    has_connection_close_been_seen = true;
                }
                else if (ah_i_http_header_value_find_csv(header.value, "keep-alive", NULL) == AH_ENONE) {
                    cln->_is_keeping_connection_open = true;
                }
            }

            cln->_cbs->on_recv_header(cln, header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_chunk_line:
    case S_IN_STATE_CHUNK_LINE: {
        size_t chunk_length;
        const char* ext;

        err = ah_i_http_parse_chunk_line(&in->rw, &chunk_length, &ext);
        if (err != AH_ENONE) {
            goto handle_parse_err;
        }

        if (cln->_cbs->on_recv_chunk_line != NULL) {
            cln->_cbs->on_recv_chunk_line(cln, chunk_length, ext);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }

        if (chunk_length == 0u) {
            ah_assert_if_debug(cln->_in_n_expected_bytes == 0u);
            cln->_in_state = S_IN_STATE_TRAILER;
            goto state_trailer;
        }

        cln->_in_n_expected_bytes = chunk_length;
        cln->_in_state = S_IN_STATE_CHUNK_DATA;
        goto state_chunk_data;
    }

    state_data:
    state_chunk_data:
    case S_IN_STATE_DATA:
    case S_IN_STATE_CHUNK_DATA: {
        size_t nread = ah_rw_get_readable_size(&in->rw);

        if (nread == 0u) {
            return;
        }

        if (nread > cln->_in_n_expected_bytes) {
            nread = cln->_in_n_expected_bytes;
        }

        cln->_in_n_expected_bytes -= nread;

        cln->_cbs->on_recv_data(cln, in);
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
            err = ah_i_http_parse_header(&in->rw, &header);
            if (err != AH_ENONE) {
                goto handle_parse_err;
            }

            if (header.name == NULL) {
                goto state_end;
            }

            cln->_cbs->on_recv_header(cln, header);
            if (!ah_tcp_conn_is_readable(&cln->_conn)) {
                return;
            }
        }
    }

    state_end : {
        cln->_cbs->on_recv_end(cln, AH_ENONE);
        if (!ah_tcp_conn_is_readable(&cln->_conn)) {
            return;
        }

        if (!cln->_is_keeping_connection_open) {
            if (ah_tcp_conn_is_closed(conn)) {
                return;
            }

            if (cln->_is_local) {
                err = ah_tcp_conn_close(conn);
            }
            else {
                err = ah_tcp_conn_shutdown(conn, AH_TCP_SHUTDOWN_RD);
            }
            if (err != AH_ENONE) {
                goto report_err_and_close_conn;
            }

            return;
        }

        if (cln->_is_local) {
            if (cln->_in_n_expected_responses == 0u) {
                err = AH_EINTERN;
                goto report_err_and_close_conn;
            }

            cln->_in_n_expected_responses -= 1u;

            if (cln->_in_n_expected_responses == 0u) {
                if (ah_rw_get_readable_size(&in->rw) != 0u) {
                    err = AH_ESTATE;
                    goto report_err_and_close_conn;
                }
                cln->_in_state = S_IN_STATE_INIT;
                return;
            }
        }

        cln->_in_state = S_IN_STATE_LINE;
        goto state_stat_line;
    }

    default:
        ah_unreachable();
    }

handle_parse_err:
    if (err != AH_EAGAIN) {
        goto report_err_and_close_conn;
    }
    err = ah_tcp_in_repackage(in);
    if (err != AH_ENONE) {
        if (err == AH_ENOSPC) {
            err = AH_EOVERFLOW;
        }
        goto report_err_and_close_conn;
    }
    return;

report_err_and_close_conn:
    cln->_cbs->on_recv_end(cln, err);
    if (!ah_tcp_conn_is_closed(conn)) {
        (void) ah_tcp_conn_close(conn);
    }
}

ah_extern ah_err_t ah_http_client_send_head(ah_http_client_t* cln, ah_http_head_t* head)
{
    if (cln == NULL || head == NULL) {
        return AH_EINVAL;
    }
    if (head->version.major != 1u || head->version.minor > 9u) {
        return AH_EPROTONOSUPPORT;
    }

    bool is_empty = ah_i_list_is_empty(&cln->_out_queue);

    ah_i_list_push(&cln->_out_queue, &head->_list_entry, 0);

    if (is_empty) {
        s_write_first_head_in_out_queue(cln);
    }

    return AH_ENONE;
}

static void s_write_first_head_in_out_queue(ah_http_client_t* cln)
{
    ah_assert_if_debug(cln != NULL);

    ah_err_t err;
    ah_http_head_t* head;

try_next:
    head = ah_i_list_peek(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL) {
        err = AH_EINTERN;
        goto handle_err;
    }

    head->_out = ah_tcp_out_alloc();
    if (head->_out == NULL) {
        err = AH_ENOMEM;
        goto handle_err;
    }

    // Only this client may free the output buffer we just allocated.
    head->_out->_owner = cln;

    ah_rw_t rw = ah_rw_from_writable_buf(&head->_out->buf);

    // Write request/status line to head buffer.
    if (cln->_is_local) {
        (void) ah_i_http_write_cstr(&rw, head->line);
        (void) ah_rw_write1(&rw, ' ');
    }
    (void) ah_i_http_write_cstr(&rw, "HTTP/1.");
    (void) ah_rw_write1(&rw, '0' + head->version.minor);
    if (!cln->_is_local) {
        (void) ah_rw_write1(&rw, ' ');
        (void) ah_i_http_write_cstr(&rw, head->line);
    }
    (void) ah_i_http_write_crlf(&rw);

    // Write host header to head buffer of outgoing request, if the HTTP version
    // is 1.1 or higher and no such header has been explicitly provided.
    if (cln->_is_local && head->version.minor != 0u) {
        bool host_is_not_specified = true;
        if (head->headers != NULL) {
            for (ah_http_header_t* header = &head->headers[0u]; header->name != NULL; header = &header[1u]) {
                if (ah_i_http_header_name_eq("host", header->name)) {
                    host_is_not_specified = false;
                    break;
                }
            }
        }

        if (host_is_not_specified) {
            (void) ah_i_http_write_cstr(&rw, "host:");

            ah_sockaddr_t raddr = *cln->_raddr;
            if (raddr.as_any.family == AH_SOCKFAMILY_IPV6 && raddr.as_ipv6.zone_id != 0u) {
                raddr.as_ipv6.zone_id = 0u;
            }

            ah_buf_t buf = ah_rw_get_writable_as_buf(&rw);

            size_t nwritten = buf.size;
            err = ah_sockaddr_stringify(&raddr, (char*) buf.base, &nwritten);
            if (err != AH_ENONE) {
                if (err == AH_ENOSPC) {
                    err = AH_EOVERFLOW;
                }
                goto handle_err;
            }
            (void) ah_rw_juken(&rw, nwritten);

            (void) ah_i_http_write_crlf(&rw);
        }
    }

    // Write other headers to head buffer.
    if (head->headers != NULL) {
        for (ah_http_header_t* header = &head->headers[0u]; header->name != NULL; header = &header[1u]) {
            (void) ah_i_http_write_cstr(&rw, header->name);
            (void) ah_rw_write1(&rw, ':');
            (void) ah_i_http_write_cstr(&rw, header->value);
            (void) ah_i_http_write_crlf(&rw);
        }
    }

    if (!ah_i_http_write_crlf(&rw)) {
        err = AH_EOVERFLOW;
        goto handle_err;
    }

    head->_out->buf = ah_rw_get_readable_as_buf(&rw);

    // Send message with request line and headers.
    err = ah_tcp_conn_write(&cln->_conn, head->_out);
    if (err != AH_ENONE) {
        goto handle_err;
    }
    head->_n_pending_tcp_outs = 1u;

    return;

handle_err:
    cln->_cbs->on_send(cln, head, err);

    if (!ah_tcp_conn_is_writable(&cln->_conn)) {
        return;
    }

    if (ah_i_list_is_empty(&cln->_out_queue)) {
        return;
    }

    goto try_next;
}

static void s_on_write(ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    (void) out;

    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    // We must only free this buffer if we allocated it (i.e. we own the buffer).
    if (out->_owner == cln) {
        ah_tcp_out_free(out);
    }

    ah_http_head_t* head = ah_i_list_peek(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL && err == AH_ENONE) {
        err = AH_EINTERN;
    }

    if (err == AH_ENONE) {
        if (head->_n_pending_tcp_outs == 0u) {
            err = AH_EINTERN;
        }
        else {
            head->_n_pending_tcp_outs -= 1u;
            if (head->_n_pending_tcp_outs != 0u || !head->_is_done_adding_tcp_outs) {
                return;
            }
        }
    }

    s_finalize_and_discard_out_queue_head(cln, err);
}

static void s_finalize_and_discard_out_queue_head(ah_http_client_t* cln, ah_err_t err)
{
    ah_assert_if_debug(cln != NULL);

    ah_http_head_t* head = ah_i_list_pop(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL && err == AH_ENONE) {
        err = AH_EINTERN;
    }

    cln->_cbs->on_send(cln, head, err);

    if (cln->_is_local) {
        if (err == AH_ENONE) {
            cln->_in_n_expected_responses += 1u;
        }
    }
    else {
        ah_tcp_conn_t* conn = ah_http_client_get_conn(cln);
        if (!ah_tcp_conn_is_readable(conn)) {
            (void) ah_tcp_conn_close(conn);
            return;
        }
    }

    if (!ah_tcp_conn_is_writable(&cln->_conn)) {
        return;
    }

    if (ah_i_list_is_empty(&cln->_out_queue)) {
        return;
    }

    s_write_first_head_in_out_queue(cln);
}

ah_extern ah_err_t ah_http_client_send_data(ah_http_client_t* cln, ah_tcp_out_t* out)
{
    if (cln == NULL || out == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err;

    ah_http_head_t* head = ah_i_list_peek(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL) {
        return AH_ESTATE;
    }

    err = ah_add_uint16(head->_n_pending_tcp_outs, 1u, &head->_n_pending_tcp_outs);
    if (err != AH_ENONE) {
        return err;
    }

    err = ah_tcp_conn_write(&cln->_conn, out);
    if (err != AH_ENONE) {
        return err;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_send_end(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }

    ah_http_head_t* head = ah_i_list_peek(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL) {
        return AH_ESTATE;
    }

    head->_is_done_adding_tcp_outs = true;

    if (head->_n_pending_tcp_outs > 0u) {
        return AH_ENONE;
    }

    s_finalize_and_discard_out_queue_head(cln, AH_ENONE);

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

    ah_http_head_t* head = ah_i_list_peek(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL) {
        return AH_ESTATE;
    }

    chunk->_out = ah_tcp_out_alloc();
    if (chunk->_out == NULL) {
        err = AH_ENOMEM;
        goto report_err_and_try_next;
    }

    ah_rw_t rw;
    ah_rw_from_writable_buf(&chunk->_out->buf);

    // Write chunk line to buffer.
    (void) ah_i_http_write_size_as_string(&rw, chunk->data.buf.size, 16u);
    if (chunk->ext != NULL) {
        (void) ah_i_http_write_cstr(&rw, chunk->ext);
    }
    if (!ah_i_http_write_crlf(&rw)) {
        err = AH_EOVERFLOW;
        goto report_err_and_try_next;
    }

    // Prepare message with chunk line.
    chunk->_out->buf = ah_rw_get_readable_as_buf(&rw);

    err = ah_add_uint16(head->_n_pending_tcp_outs, 2u, &head->_n_pending_tcp_outs);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }

    // Send message with chunk line.
    err = ah_tcp_conn_write(&cln->_conn, chunk->_out);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }

    // Send message with data.
    err = ah_tcp_conn_write(&cln->_conn, &chunk->data);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }

    return AH_ENONE;

report_err_and_try_next:
    s_finalize_and_discard_out_queue_head(cln, err);
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

    ah_http_head_t* head = ah_i_list_peek(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
    if (head == NULL) {
        return AH_ESTATE;
    }

    trailer->_out = ah_tcp_out_alloc();
    if (trailer->_out == NULL) {
        err = AH_ENOMEM;
        goto report_err_and_try_next;
    }

    ah_rw_t rw;
    ah_rw_from_writable_buf(&trailer->_out->buf);

    // Write trailer chunk line to buffer.
    (void) ah_rw_write1(&rw, '0');
    if (trailer->ext != NULL) {
        (void) ah_i_http_write_cstr(&rw, trailer->ext);
    }
    if (!ah_i_http_write_crlf(&rw)) {
        err = AH_EOVERFLOW;
        goto report_err_and_try_next;
    }

    // Write trailer headers to buffer.
    if (trailer->headers != NULL) {
        ah_http_header_t* header = &trailer->headers[0u];
        for (; header->name != NULL; header = &header[1u]) {
            (void) ah_i_http_write_cstr(&rw, header->name);
            (void) ah_rw_write1(&rw, ':');
            (void) ah_i_http_write_cstr(&rw, header->value);
            (void) ah_i_http_write_crlf(&rw);
        }
    }
    (void) ah_i_http_write_crlf(&rw);

    // Prepare message with complete trailer.
    trailer->_out->buf = ah_rw_get_readable_as_buf(&rw);

    // Send message with complete trailer.
    err = ah_tcp_conn_write(&cln->_conn, trailer->_out);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }

    err = ah_add_uint16(head->_n_pending_tcp_outs, 1u, &head->_n_pending_tcp_outs);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }

    return ah_http_client_send_end(cln);

report_err_and_try_next:
    s_finalize_and_discard_out_queue_head(cln, err);
    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_close(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_close(&cln->_conn);
}

static void s_on_close(ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_conn_to_client(conn);

    for (ah_http_head_t* head;;) {
        head = ah_i_list_pop(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
        if (head == NULL) {
            break;
        }
        cln->_cbs->on_send(cln, head, AH_ECANCELED);
    }

    cln->_cbs->on_close(cln, err);
}

ah_extern ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return &cln->_conn;
}

ah_extern ah_err_t ah_http_client_get_laddr(const ah_http_client_t* cln, ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_get_laddr(&cln->_conn, laddr);
}

ah_extern ah_err_t ah_http_client_get_raddr(const ah_http_client_t* cln, ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_get_raddr(&cln->_conn, raddr);
}

ah_extern ah_loop_t* ah_http_client_get_loop(const ah_http_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return ah_tcp_conn_get_loop(&cln->_conn);
}

ah_extern void* ah_http_client_get_user_data(const ah_http_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return ah_tcp_conn_get_user_data(&cln->_conn);
}

ah_extern void ah_http_client_set_user_data(ah_http_client_t* cln, void* user_data)
{
    if (cln != NULL) {
        ah_tcp_conn_set_user_data(&cln->_conn, user_data);
    }
}

void ah_i_http_client_init_accepted(ah_http_client_t* cln, ah_http_server_t* srv, const ah_sockaddr_t* raddr)
{
    ah_assert_if_debug(cln != NULL);
    ah_assert_if_debug(!ah_tcp_conn_is_closed(&cln->_conn));
    ah_assert_if_debug(srv != NULL);
    ah_assert_if_debug(raddr != NULL);

    cln->_raddr = raddr;
    cln->_cbs = srv->_client_cbs;
    cln->_in_state = S_IN_STATE_INIT;
}

const ah_tcp_conn_cbs_t* ah_i_http_client_get_conn_cbs(void)
{
    return &s_cbs;
}
