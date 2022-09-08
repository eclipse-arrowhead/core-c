// SPDX-License-Identifier: EPL-2.0


#include "http-client.h"
#include "http-parser.h"
#include "http-utils.h"
#include "http-writer.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>
#include <ah/sock.h>

static void s_conn_on_open(void* cln_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_connect(void* cln_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_read(void* cln_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_conn_on_write(void* cln_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_conn_on_close(void* cln_, ah_tcp_conn_t* conn, ah_err_t err);

static void s_finalize_and_discard_out_queue_head(ah_http_client_t* cln, ah_err_t err);
static void s_write_first_head_in_out_queue(ah_http_client_t* cln);

const ah_tcp_conn_cbs_t ah_i_http_conn_cbs = {
    .on_open = s_conn_on_open,
    .on_connect = s_conn_on_connect,
    .on_read = s_conn_on_read,
    .on_write = s_conn_on_write,
    .on_close = s_conn_on_close,
};

ah_extern ah_err_t ah_http_client_init(ah_http_client_t* cln, ah_loop_t* loop, ah_tcp_trans_t trans, ah_http_client_obs_t obs)
{
    if (cln == NULL || !ah_http_client_cbs_is_valid(obs.cbs)) {
        return AH_EINVAL;
    }

    ah_tcp_conn_t* conn = malloc(sizeof(ah_tcp_conn_t));
    if (conn == NULL) {
        return AH_ENOMEM;
    }

    ah_err_t err = ah_tcp_conn_init(conn, loop, trans, (ah_tcp_conn_obs_t) { &ah_i_http_conn_cbs, cln });
    if (err != AH_ENONE) {
        free(conn);
        return err;
    }

    *cln = (ah_http_client_t) {
        ._conn = conn,
        ._obs = obs,
        ._in_state = AH_I_HTTP_CLIENT_IN_STATE_INIT,
        ._is_local = true,
    };

    return AH_ENONE;
}

ah_extern ah_err_t ah_http_client_open(ah_http_client_t* cln, const ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_open(cln->_conn, laddr);
}

static void s_conn_on_open(void* cln_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_ctx_to_client(cln_);

    (void) conn;

    cln->_obs.cbs->on_open(cln->_obs.ctx, cln, err);
}

ah_extern ah_err_t ah_http_client_connect(ah_http_client_t* cln, const ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    ah_err_t err = ah_tcp_conn_connect(cln->_conn, raddr);
    if (err == AH_ENONE) {
        cln->_raddr = raddr;
    }
    return err;
}

static void s_conn_on_connect(void* cln_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_ctx_to_client(cln_);

    cln->_obs.cbs->on_connect(cln->_obs.ctx, cln, err);
    if (err != AH_ENONE || ah_tcp_conn_is_closed(conn)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (err != AH_ENONE) {
        goto handle_err;
    }

    return;

handle_err:
    cln->_obs.cbs->on_recv_end(cln->_obs.ctx, cln, err);
}

static void s_conn_on_read(void* cln_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_ctx_to_client(cln_);

    if (err != AH_ENONE) {
        goto report_err_and_close_conn;
    }

    switch (cln->_in_state) {
    case AH_I_HTTP_CLIENT_IN_STATE_INIT: {
        if (cln->_is_local && cln->_in_n_expected_responses == 0u) {
            err = AH_ESTATE;
            goto report_err_and_close_conn;
        }

        cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_LINE;
        goto state_stat_line;
    }

    state_stat_line:
    case AH_I_HTTP_CLIENT_IN_STATE_LINE: {
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

        cln->_obs.cbs->on_recv_line(cln->_obs.ctx, cln, line, version);
        if (!ah_tcp_conn_is_readable(cln->_conn)) {
            return;
        }

        cln->_is_keeping_connection_open = version.minor != 0u;

        cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_HEADERS;
        goto state_headers;
    }

    state_headers:
    case AH_I_HTTP_CLIENT_IN_STATE_HEADERS: {
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
                if (cln->_obs.cbs->on_recv_headers != NULL) {
                    cln->_obs.cbs->on_recv_headers(cln->_obs.ctx, cln);
                    if (!ah_tcp_conn_is_readable(cln->_conn)) {
                        return;
                    }
                }

                if (has_transfer_encoding_chunked_been_seen) {
                    if (has_content_length_been_seen && content_length != 0u) {
                        err = AH_EBADMSG;
                        goto report_err_and_close_conn;
                    }
                    cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_CHUNK_LINE;
                    goto state_chunk_line;
                }

                if (!has_content_length_been_seen || content_length == 0u) {
                    goto state_end;
                }

                cln->_in_n_expected_bytes = content_length;
                cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_DATA;
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
                    // See https://rfc-editor.org/rfc/rfc7230#section-3.3.3.
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

            cln->_obs.cbs->on_recv_header(cln->_obs.ctx, cln, header);
            if (!ah_tcp_conn_is_readable(cln->_conn)) {
                return;
            }
        }
    }

    state_chunk_line:
    case AH_I_HTTP_CLIENT_IN_STATE_CHUNK_LINE: {
        size_t chunk_length;
        const char* ext;

        err = ah_i_http_parse_chunk_line(&in->rw, &chunk_length, &ext);
        if (err != AH_ENONE) {
            goto handle_parse_err;
        }

        if (cln->_obs.cbs->on_recv_chunk_line != NULL) {
            cln->_obs.cbs->on_recv_chunk_line(cln->_obs.ctx, cln, chunk_length, ext);
            if (!ah_tcp_conn_is_readable(cln->_conn)) {
                return;
            }
        }

        if (chunk_length == 0u) {
            ah_assert_if_debug(cln->_in_n_expected_bytes == 0u);
            cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_TRAILER;
            goto state_trailer;
        }

        cln->_in_n_expected_bytes = chunk_length;
        cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_CHUNK_DATA;
        goto state_chunk_data;
    }

    state_data:
    state_chunk_data:
    case AH_I_HTTP_CLIENT_IN_STATE_DATA:
    case AH_I_HTTP_CLIENT_IN_STATE_CHUNK_DATA: {
        size_t nread = ah_rw_get_readable_size(&in->rw);

        if (nread == 0u) {
            return;
        }

        if (nread > cln->_in_n_expected_bytes) {
            nread = cln->_in_n_expected_bytes;
        }

        cln->_in_n_expected_bytes -= nread;

        cln->_obs.cbs->on_recv_data(cln->_obs.ctx, cln, in);
        if (!ah_tcp_conn_is_readable(cln->_conn)) {
            return;
        }

        if (cln->_in_n_expected_bytes == 0u) {
            if (cln->_in_state == AH_I_HTTP_CLIENT_IN_STATE_DATA) {
                goto state_end;
            }
            cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_CHUNK_LINE;
            goto state_chunk_line;
        }

        return;
    }

    state_trailer:
    case AH_I_HTTP_CLIENT_IN_STATE_TRAILER: {
        for (;;) {
            ah_http_header_t header;
            err = ah_i_http_parse_header(&in->rw, &header);
            if (err != AH_ENONE) {
                goto handle_parse_err;
            }

            if (header.name == NULL) {
                goto state_end;
            }

            cln->_obs.cbs->on_recv_header(cln->_obs.ctx, cln, header);
            if (!ah_tcp_conn_is_readable(cln->_conn)) {
                return;
            }
        }
    }

    state_end : {
        cln->_obs.cbs->on_recv_end(cln->_obs.ctx, cln, AH_ENONE);
        if (!ah_tcp_conn_is_readable(cln->_conn)) {
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
                cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_INIT;
                return;
            }
        }

        cln->_in_state = AH_I_HTTP_CLIENT_IN_STATE_LINE;
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
        goto report_err_and_close_conn;
    }
    return;

report_err_and_close_conn:
    cln->_obs.cbs->on_recv_end(cln->_obs.ctx, cln, err);
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

    // Only this cln may free the output buffer we just allocated.
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
                if (err == AH_EOVERFLOW) {
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
    err = ah_tcp_conn_write(cln->_conn, head->_out);
    if (err != AH_ENONE) {
        goto handle_err;
    }
    head->_n_pending_tcp_outs = 1u;

    return;

handle_err:
    cln->_obs.cbs->on_send(cln->_obs.ctx, cln, head, err);

    if (!ah_tcp_conn_is_writable(cln->_conn)) {
        return;
    }

    if (ah_i_list_is_empty(&cln->_out_queue)) {
        return;
    }

    goto try_next;
}

static void s_conn_on_write(void* cln_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_ctx_to_client(cln_);

    (void) conn;

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

    cln->_obs.cbs->on_send(cln->_obs.ctx, cln, head, err);

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

    if (!ah_tcp_conn_is_writable(cln->_conn)) {
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

    err = ah_tcp_conn_write(cln->_conn, out);
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
        return AH_ESYNTAX;
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
    err = ah_tcp_conn_write(cln->_conn, chunk->_out);
    if (err != AH_ENONE) {
        goto report_err_and_try_next;
    }

    // Send message with data.
    err = ah_tcp_conn_write(cln->_conn, &chunk->data);
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
        return AH_ESYNTAX;
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
    err = ah_tcp_conn_write(cln->_conn, trailer->_out);
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
    return ah_tcp_conn_close(cln->_conn);
}

ah_extern ah_err_t ah_http_client_term(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }

    ah_err_t err = ah_tcp_conn_term(cln->_conn);
    if (err != AH_ENONE) {
        return err;
    }

    if (cln->_is_local) {
        free(cln->_conn);
    }

    if (cln->_owning_slab != NULL) {
        ah_i_slab_free(cln->_owning_slab, cln);
    }

    return AH_ENONE;
}

static void s_conn_on_close(void* cln_, ah_tcp_conn_t* conn, ah_err_t err)
{
    ah_http_client_t* cln = ah_i_http_ctx_to_client(cln_);

    (void) conn;

    for (ah_http_head_t* head;;) {
        head = ah_i_list_pop(&cln->_out_queue, offsetof(ah_http_head_t, _list_entry));
        if (head == NULL) {
            break;
        }
        cln->_obs.cbs->on_send(cln->_obs.ctx, cln, head, AH_ECANCELED);
    }

    cln->_obs.cbs->on_close(cln->_obs.ctx, cln, err);
}

ah_extern ah_tcp_conn_t* ah_http_client_get_conn(ah_http_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return cln->_conn;
}

ah_extern ah_err_t ah_http_client_get_laddr(const ah_http_client_t* cln, ah_sockaddr_t* laddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_get_laddr(cln->_conn, laddr);
}

ah_extern ah_err_t ah_http_client_get_raddr(const ah_http_client_t* cln, ah_sockaddr_t* raddr)
{
    if (cln == NULL) {
        return AH_EINVAL;
    }
    return ah_tcp_conn_get_raddr(cln->_conn, raddr);
}

ah_extern ah_loop_t* ah_http_client_get_loop(const ah_http_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return ah_tcp_conn_get_loop(cln->_conn);
}

ah_extern void* ah_http_client_get_obs_ctx(const ah_http_client_t* cln)
{
    if (cln == NULL) {
        return NULL;
    }
    return cln->_obs.ctx;
}

ah_extern bool ah_http_client_cbs_is_valid(const ah_http_client_cbs_t* cbs)
{
    return cbs != NULL
        && cbs->on_open != NULL
        && cbs->on_connect != NULL
        && cbs->on_send != NULL
        && cbs->on_recv_line != NULL
        && cbs->on_recv_header != NULL
        && cbs->on_recv_data != NULL
        && cbs->on_recv_end != NULL
        && cbs->on_close != NULL;
}
