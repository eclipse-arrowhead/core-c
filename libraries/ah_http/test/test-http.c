// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>
#include <ah/loop.h>
#include <ah/sock.h>
#include <ah/unit.h>

struct s_http_client_user_data {
    ah_http_out_t* on_connect_send_msg;
    ah_http_out_t* on_recv_end_send_msg;
    ah_sockaddr_t* on_open_connect_to_raddr;
    size_t* close_call_counter;

    bool did_call_open_cb;
    bool did_call_connect_cb;
    bool did_call_send_cb;
    bool did_call_recv_line_cb;
    bool did_call_recv_header_cb;
    bool did_call_recv_headers_cb;
    bool did_call_recv_chunk_line_cb;
    bool did_call_recv_data_cb;
    bool did_call_recv_end_cb;
    bool did_call_close_cb;

    ah_unit_t* unit;
};

struct s_http_server_user_data {
    ah_sockaddr_t on_open_store_laddr;

    ah_http_client_t* on_listen_open_lclient;
    struct s_http_client_user_data on_client_accept_provide_user_data;

    bool did_call_open_cb;
    bool did_call_listen_cb;
    bool did_call_accept_cb;
    bool did_call_close_cb;

    ah_unit_t* unit;
};

static void s_should_send_and_receive_short_message(ah_unit_t* unit);

void test_http(ah_unit_t* unit)
{
    s_should_send_and_receive_short_message(unit);
}

void on_client_open(ah_http_client_t* cln, ah_err_t err);
void on_client_connect(ah_http_client_t* cln, ah_err_t err);
void on_client_close(ah_http_client_t* cln, ah_err_t err);
void on_client_send_done(ah_http_client_t* cln, ah_http_out_t* msg, ah_err_t err);
void on_client_recv_line(ah_http_client_t* cln, const char* line, ah_http_ver_t version);
void on_client_recv_header(ah_http_client_t* cln, ah_http_header_t header);
void on_client_recv_headers(ah_http_client_t* cln);
void on_client_recv_chunk_line(ah_http_client_t* cln, size_t size, const char* ext);
void on_client_recv_data(ah_http_client_t* cln, ah_tcp_in_t* in);
void on_client_recv_end(ah_http_client_t* cln, ah_err_t err);

void s_on_server_open(ah_http_server_t* srv, ah_err_t err);
void s_on_server_listen(ah_http_server_t* srv, ah_err_t err);
void s_on_server_accept(ah_http_server_t* srv, ah_http_client_t* client, ah_err_t err);
void s_on_server_close(ah_http_server_t* srv, ah_err_t err);

static const ah_http_client_cbs_t s_client_cbs = {
    .on_open = on_client_open,
    .on_connect = on_client_connect,
    .on_close = on_client_close,
    .on_send = on_client_send_done,
    .on_recv_line = on_client_recv_line,
    .on_recv_header = on_client_recv_header,
    .on_recv_headers = on_client_recv_headers,
    .on_recv_chunk_line = on_client_recv_chunk_line,
    .on_recv_data = on_client_recv_data,
    .on_recv_end = on_client_recv_end,
};

static const ah_http_server_cbs_t s_server_cbs = {
    .on_open = s_on_server_open,
    .on_listen = s_on_server_listen,
    .on_accept = s_on_server_accept,
    .on_close = s_on_server_close,
};

void on_client_open(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (user_data->on_open_connect_to_raddr != NULL) {
        err = ah_http_client_connect(cln, user_data->on_open_connect_to_raddr);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }
    }

    user_data->did_call_open_cb = true;
}

void on_client_connect(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (user_data->on_connect_send_msg != NULL) {
        err = ah_http_client_send(cln, user_data->on_connect_send_msg);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }
    }

    user_data->did_call_connect_cb = true;
}

void on_client_close(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    *user_data->close_call_counter += 1u;
    if (*user_data->close_call_counter == 2u) {
        ah_loop_t* loop = ah_http_client_get_loop(cln);
        if (!ah_unit_assert(unit, loop != NULL, "loop == NULL")) {
            return;
        }

        err = ah_loop_term(loop);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }
    }

    user_data->did_call_close_cb = true;
}

void on_client_send_done(ah_http_client_t* cln, ah_http_out_t* msg, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (user_data->on_connect_send_msg != NULL) {
        (void) ah_unit_assert_cstr_eq(unit, "GET /things/1234", msg->line);
    }
    if (user_data->on_recv_end_send_msg != NULL) {
        (void) ah_unit_assert_cstr_eq(unit, "200 OK", msg->line);
    }

    user_data->did_call_send_cb = true;
}

void on_client_recv_line(ah_http_client_t* cln, const char* line, ah_http_ver_t version)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (user_data->on_connect_send_msg == NULL) {
        (void) ah_unit_assert_cstr_eq(unit, "GET /things/1234", line);
    }
    if (user_data->on_recv_end_send_msg == NULL) {
        (void) ah_unit_assert_cstr_eq(unit, "200 OK", line);
    }

    (void) ah_unit_assert_unsigned_eq(unit, 1u, version.major);
    (void) ah_unit_assert_unsigned_eq(unit, 1u, version.minor);

    user_data->did_call_recv_line_cb = true;
}

void on_client_recv_header(ah_http_client_t* cln, ah_http_header_t header)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    (void) header;
    user_data->did_call_recv_header_cb = true;
}

void on_client_recv_headers(ah_http_client_t* cln)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    user_data->did_call_recv_headers_cb = true;
}

void on_client_recv_chunk_line(ah_http_client_t* cln, size_t size, const char* ext)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    (void) size;
    (void) ext;
    user_data->did_call_recv_chunk_line_cb = true;
}

void on_client_recv_data(ah_http_client_t* cln, ah_tcp_in_t* in)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (user_data->on_connect_send_msg != NULL) {
        if (!ah_unit_assert_unsigned_eq(unit, 28u, in->nread)) {
            return;
        }
        ah_unit_assert_mem_eq(unit, "{\"text\":\"Hello, Arrowhead!\"}", ah_buf_get_base_const(&in->buf), 28u);
    }

    user_data->did_call_recv_data_cb = true;
}

void on_client_recv_end(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_t* unit = user_data->unit;

    if (err == AH_EEOF) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (user_data->on_recv_end_send_msg != NULL) {
        err = ah_http_client_send(cln, user_data->on_recv_end_send_msg);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }
    }

    user_data->did_call_recv_end_cb = true;
}

void s_on_server_open(ah_http_server_t* srv, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_tcp_listener_t* ln = ah_http_server_get_listener(srv);
    if (!ah_unit_assert(unit, ln != NULL, "ln == NULL")) {
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, true);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_listener_get_laddr(ln, &user_data->on_open_store_laddr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_http_server_listen(srv, 1, &s_client_cbs);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

void s_on_server_listen(ah_http_server_t* srv, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_t* unit = user_data->unit;

    if (err == AH_ECANCELED) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_err_eq(unit, AH_ENONE, err);
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_http_client_open(user_data->on_listen_open_lclient, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_listen_cb = true;
}

void s_on_server_close(ah_http_server_t* srv, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_close_cb = true;
}

void s_on_server_accept(ah_http_server_t* srv, ah_http_client_t* client, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_t* unit = user_data->unit;

    if (err == AH_ECANCELED) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_err_eq(unit, AH_ENONE, err);
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_http_client_set_user_data(client, &user_data->on_client_accept_provide_user_data);

    user_data->did_call_accept_cb = true;
}

static void s_should_send_and_receive_short_message(ah_unit_t* unit)
{
    ah_err_t err;

    // Setup user data.

    size_t close_call_counter = 0u;

    struct s_http_server_user_data server_user_data = {
        .on_client_accept_provide_user_data = (struct s_http_client_user_data) {
            .on_recv_end_send_msg = &(ah_http_out_t) {
                .line = "200 OK",
                .version = { 1u, 1u },
                .headers = (ah_http_header_t[]) {
                    { "content-type", "application/json" },
                    { NULL, NULL },
                },
                .body = ah_buf_from((uint8_t*) "{\"text\":\"Hello, Arrowhead!\"}", 28u),
            },
            .close_call_counter = &close_call_counter,
            .unit = unit,
        },
        .unit = unit,
    };

    struct s_http_client_user_data lclient_user_data = {
        .on_open_connect_to_raddr = &server_user_data.on_open_store_laddr,
        .on_connect_send_msg = &(ah_http_out_t) {
            .line = "GET /things/1234",
            .version = { 1u, 1u },
            .headers = (ah_http_header_t[]) {
                { "accept", "application/json" },
                { "connection", "close" },
                { NULL, NULL },
            },
            .body = (ah_buf_t) { 0u },
        },
        .close_call_counter = &close_call_counter,
        .unit = unit,
    };

    // Setup event loop.
    ah_loop_t loop;
    err = ah_loop_init(&loop, &(ah_loop_opts_t) { .capacity = 4u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Setup plain TCP transport.
    ah_tcp_trans_t transport = ah_tcp_trans_get_default();

    // Setup HTTP server.
    ah_http_server_t server;
    err = ah_http_server_init(&server, &loop, transport, &s_server_cbs);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    ah_http_server_set_user_data(&server, &server_user_data);

    // Setup local HTTP client.
    ah_http_client_t lclient;
    err = ah_http_client_init(&lclient, &loop, transport, &s_client_cbs);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    ah_http_client_set_user_data(&lclient, &lclient_user_data);

    // Store reference to local client so the server can open it later.
    server_user_data.on_listen_open_lclient = &lclient;

    // Open local HTTP server, which will open the local HTTP client, and so on.
    err = ah_http_server_open(&server, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Submit issued events for execution.
    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 1 * AH_TIMEDIFF_S, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Check results.

    struct s_http_client_user_data* lclient_data = &lclient_user_data;
    (void) ah_unit_assert(unit, lclient_data->did_call_open_cb, "`lclient` s_on_client_open() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_connect_cb, "`lclient` s_on_client_connect() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_close_cb, "`lclient` s_on_client_close() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_send_cb, "`lclient` s_on_client_send_done() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_recv_line_cb, "`lclient` s_on_client_recv_line() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_recv_header_cb, "`lclient` s_on_client_recv_header() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_recv_headers_cb, "`lclient` s_on_client_recv_headers() not called");
    (void) ah_unit_assert(unit, !lclient_data->did_call_recv_chunk_line_cb, "`lclient` s_on_client_recv_chunk_line() was called");
    (void) ah_unit_assert(unit, lclient_data->did_call_recv_data_cb, "`lclient` s_on_client_recv_data() not called");
    (void) ah_unit_assert(unit, lclient_data->did_call_recv_end_cb, "`lclient` s_on_client_recv_end() not called");

    struct s_http_server_user_data* server_data = &server_user_data;
    (void) ah_unit_assert(unit, server_data->did_call_open_cb, "s_on_server_open() not called");
    (void) ah_unit_assert(unit, server_data->did_call_listen_cb, "s_on_server_listen() not called");
    (void) ah_unit_assert(unit, server_data->did_call_close_cb, "s_on_server_close() not called");
    (void) ah_unit_assert(unit, server_data->did_call_accept_cb, "s_on_server_accept() not called");

    struct s_http_client_user_data* rclient_data = &server_data->on_client_accept_provide_user_data;
    (void) ah_unit_assert(unit, !rclient_data->did_call_open_cb, "`rclient` s_on_client_open() was called");
    (void) ah_unit_assert(unit, !rclient_data->did_call_connect_cb, "`rclient` s_on_client_connect() was called");
    (void) ah_unit_assert(unit, rclient_data->did_call_close_cb, "`rclient` s_on_client_close() not called");
    (void) ah_unit_assert(unit, rclient_data->did_call_send_cb, "`rclient` s_on_client_send_done() not called");
    (void) ah_unit_assert(unit, rclient_data->did_call_recv_line_cb, "`rclient` s_on_client_recv_line() not called");
    (void) ah_unit_assert(unit, rclient_data->did_call_recv_header_cb, "`rclient` s_on_client_recv_header() not called");
    (void) ah_unit_assert(unit, rclient_data->did_call_recv_headers_cb, "`rclient` s_on_client_recv_headers() not called");
    (void) ah_unit_assert(unit, !rclient_data->did_call_recv_chunk_line_cb, "`rclient` s_on_client_recv_chunk_line() was called");
    (void) ah_unit_assert(unit, !rclient_data->did_call_recv_data_cb, "`rclient` s_on_client_recv_data() was called");
    (void) ah_unit_assert(unit, rclient_data->did_call_recv_end_cb, "`rclient` s_on_client_recv_end() not called");

    ah_unit_assert(unit, ah_loop_is_term(&loop), "`loop` never terminated");
}
