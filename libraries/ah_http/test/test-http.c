// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/err.h>
#include <ah/loop.h>
#include <ah/sock.h>
#include <ah/unit.h>

struct s_http_client_user_data {
    ah_http_head_t* on_connect_send_head;

    ah_http_head_t* on_recv_end_send_head;
    ah_tcp_out_t* on_recv_end_send_data;

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

    ah_unit_res_t* res;
};

struct s_http_server_user_data {
    ah_sockaddr_t on_open_store_laddr;

    ah_http_client_t* on_listen_open_lclient;
    struct s_http_client_user_data on_client_accept_provide_user_data;

    bool did_call_open_cb;
    bool did_call_listen_cb;
    bool did_call_accept_cb;
    bool did_call_close_cb;

    ah_unit_res_t* res;
};

static void s_should_send_and_receive_short_message(ah_unit_res_t* res);

void test_http(ah_unit_res_t* res)
{
    s_should_send_and_receive_short_message(res);
}

void on_client_open(ah_http_client_t* cln, ah_err_t err);
void on_client_connect(ah_http_client_t* cln, ah_err_t err);
void on_client_close(ah_http_client_t* cln, ah_err_t err);
void on_client_send(ah_http_client_t* cln, ah_http_head_t* msg, ah_err_t err);
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
    .on_send = on_client_send,
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
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    if (user_data->on_open_connect_to_raddr != NULL) {
        err = ah_http_client_connect(cln, user_data->on_open_connect_to_raddr);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
    }

    user_data->did_call_open_cb = true;
}

void on_client_connect(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    if (user_data->on_connect_send_head != NULL) {
        err = ah_http_client_send_head(cln, user_data->on_connect_send_head);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
        err = ah_http_client_send_end(cln);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
    }

    user_data->did_call_connect_cb = true;
}

void on_client_close(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    *user_data->close_call_counter += 1u;
    if (*user_data->close_call_counter == 2u) {
        ah_loop_t* loop = ah_http_client_get_loop(cln);
        if (!ah_unit_assert(AH_UNIT_CTX, res, loop != NULL, "loop == NULL")) {
            return;
        }

        err = ah_loop_term(loop);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
    }

    user_data->did_call_close_cb = true;
}

void on_client_send(ah_http_client_t* cln, ah_http_head_t* msg, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    if (user_data->on_connect_send_head != NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, msg->line, "GET /things/1234");
    }
    if (user_data->on_recv_end_send_head != NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, msg->line, "200 OK");
    }

    user_data->did_call_send_cb = true;
}

void on_client_recv_line(ah_http_client_t* cln, const char* line, ah_http_ver_t version)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_res_t* res = user_data->res;

    if (user_data->on_connect_send_head == NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "GET /things/1234");
    }
    if (user_data->on_recv_end_send_head == NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "200 OK");
    }

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 1u);

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
    ah_unit_res_t* res = user_data->res;

    if (user_data->on_connect_send_head != NULL) {
        if (ah_rw_get_readable_size(&in->rw) < 28u) {
            return; // Wait for more data to arrive.
        }
        if (ah_unit_assert_eq_mem(AH_UNIT_CTX, res, in->rw.r, "{\"text\":\"Hello, Arrowhead!\"}", 28u)) {
            ah_rw_skipn(&in->rw, 28);
        }
    }

    user_data->did_call_recv_data_cb = true;
}

void on_client_recv_end(ah_http_client_t* cln, ah_err_t err)
{
    struct s_http_client_user_data* user_data = ah_http_client_get_user_data(cln);
    ah_unit_res_t* res = user_data->res;

    if (err == AH_EEOF) {
        return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    if (user_data->on_recv_end_send_head != NULL) {
        err = ah_http_client_send_head(cln, user_data->on_recv_end_send_head);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
        if (user_data->on_recv_end_send_data != NULL) {
            err = ah_http_client_send_data(cln, user_data->on_recv_end_send_data);
            if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
                return;
            }
        }
        err = ah_http_client_send_end(cln);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
    }

    user_data->did_call_recv_end_cb = true;
}

void s_on_server_open(ah_http_server_t* srv, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ah_tcp_listener_t* ln = ah_http_server_get_listener(srv);
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln == NULL")) {
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_listener_get_laddr(ln, &user_data->on_open_store_laddr);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_http_server_listen(srv, 1, &s_client_cbs);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

void s_on_server_listen(ah_http_server_t* srv, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_res_t* res = user_data->res;

    if (err == AH_ECANCELED) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_http_client_open(user_data->on_listen_open_lclient, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_listen_cb = true;
}

void s_on_server_close(ah_http_server_t* srv, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_close_cb = true;
}

void s_on_server_accept(ah_http_server_t* srv, ah_http_client_t* client, ah_err_t err)
{
    struct s_http_server_user_data* user_data = ah_http_server_get_user_data(srv);
    ah_unit_res_t* res = user_data->res;

    if (err == AH_ECANCELED) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ah_http_client_set_user_data(client, &user_data->on_client_accept_provide_user_data);

    user_data->did_call_accept_cb = true;
}

static void s_should_send_and_receive_short_message(ah_unit_res_t* res)
{
    ah_err_t err;

    // Setup user data.

    size_t close_call_counter = 0u;

    struct s_http_server_user_data server_user_data = {
        .on_client_accept_provide_user_data = (struct s_http_client_user_data) {
            .on_recv_end_send_head = &(ah_http_head_t) {
                .line = "200 OK",
                .version = { 1u, 1u },
                .headers = (ah_http_header_t[]) {
                    { "content-length", "28" },
                    { "content-type", "application/json" },
                    { NULL, NULL },
                },
            },
            .on_recv_end_send_data = &(ah_tcp_out_t) {
                .buf = ah_buf_from((uint8_t*) "{\"text\":\"Hello, Arrowhead!\"}", 28u),
            },
            .close_call_counter = &close_call_counter,
            .res = res,
        },
        .res = res,
    };

    struct s_http_client_user_data lclient_user_data = {
        .on_open_connect_to_raddr = &server_user_data.on_open_store_laddr,
        .on_connect_send_head = &(ah_http_head_t) {
            .line = "GET /things/1234",
            .version = { 1u, 1u },
            .headers = (ah_http_header_t[]) {
                { "accept", "application/json" },
                { "connection", "close" },
                { NULL, NULL },
            },
        },
        .close_call_counter = &close_call_counter,
        .res = res,
    };

    // Setup event loop.
    ah_loop_t loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup plain TCP transport.
    ah_tcp_trans_t transport = ah_tcp_trans_get_default();

    // Setup HTTP server.
    ah_http_server_t server;
    err = ah_http_server_init(&server, &loop, transport, &s_server_cbs);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    ah_http_server_set_user_data(&server, &server_user_data);

    // Setup local HTTP client.
    ah_http_client_t lclient;
    err = ah_http_client_init(&lclient, &loop, transport, &s_client_cbs);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    ah_http_client_set_user_data(&lclient, &lclient_user_data);

    // Store reference to local client so the server can open it later.
    server_user_data.on_listen_open_lclient = &lclient;

    // Open local HTTP server, which will open the local HTTP client, and so on.
    err = ah_http_server_open(&server, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Submit issued events for execution.
    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 1 * AH_TIMEDIFF_S, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Perform final cleanups.

    ah_http_server_term(&server);

    // Check results.

    struct s_http_client_user_data* lclient_data = &lclient_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_open_cb, "`lclient` s_on_client_open() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_connect_cb, "`lclient` s_on_client_connect() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_close_cb, "`lclient` s_on_client_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_send_cb, "`lclient` s_on_client_send_done() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_recv_line_cb, "`lclient` s_on_client_recv_line() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_recv_header_cb, "`lclient` s_on_client_recv_header() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_recv_headers_cb, "`lclient` s_on_client_recv_headers() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !lclient_data->did_call_recv_chunk_line_cb, "`lclient` s_on_client_recv_chunk_line() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_recv_data_cb, "`lclient` s_on_client_recv_data() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_data->did_call_recv_end_cb, "`lclient` s_on_client_recv_end() not called");

    struct s_http_server_user_data* server_data = &server_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, server_data->did_call_open_cb, "s_on_server_open() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, server_data->did_call_listen_cb, "s_on_server_listen() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, server_data->did_call_close_cb, "s_on_server_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, server_data->did_call_accept_cb, "s_on_server_accept() not called");

    struct s_http_client_user_data* rclient_data = &server_data->on_client_accept_provide_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, !rclient_data->did_call_open_cb, "`rclient` s_on_client_open() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !rclient_data->did_call_connect_cb, "`rclient` s_on_client_connect() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, rclient_data->did_call_close_cb, "`rclient` s_on_client_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, rclient_data->did_call_send_cb, "`rclient` s_on_client_send_done() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, rclient_data->did_call_recv_line_cb, "`rclient` s_on_client_recv_line() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, rclient_data->did_call_recv_header_cb, "`rclient` s_on_client_recv_header() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, rclient_data->did_call_recv_headers_cb, "`rclient` s_on_client_recv_headers() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !rclient_data->did_call_recv_chunk_line_cb, "`rclient` s_on_client_recv_chunk_line() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !rclient_data->did_call_recv_data_cb, "`rclient` s_on_client_recv_data() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, rclient_data->did_call_recv_end_cb, "`rclient` s_on_client_recv_end() not called");

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}
