// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/loop.h>
#include <ah/sock.h>
#include <ah/unit.h>

struct s_client_obs_ctx {
    ah_sockaddr_t connect_to_this_raddr_on_open_if_port_is_not_zero;
    ah_http_head_t* send_this_head_on_connect_if_not_null;
    ah_http_head_t* send_this_head_on_recv_end_if_not_null;
    ah_tcp_out_t* send_this_out_on_recv_end_if_not_null;

    size_t* client_count;

    size_t on_open_count;
    size_t on_connect_count;
    size_t on_send_count;
    size_t on_recv_line_count;
    size_t on_recv_header_count;
    size_t on_recv_headers_count;
    size_t on_recv_chunk_line_count;
    size_t on_recv_data_count;
    size_t on_recv_end_count;
    size_t on_close_count;
    size_t received_body_count;
    size_t sent_message_count;

    ah_unit_res_t* res;
};

struct s_server_obs_ctx {
    ah_http_client_t* open_this_client_on_listen;

    struct s_client_obs_ctx accepted_client_obs_ctx;

    size_t on_open_count;
    size_t on_listen_count;
    size_t on_accept_count;
    size_t on_close_count;

    ah_unit_res_t* res;
};

static void s_should_send_and_receive_short_message(ah_unit_res_t* res);

void test_http(ah_unit_res_t* res)
{
    s_should_send_and_receive_short_message(res);
}

void s_client_on_open(void* ctx_, ah_http_client_t* cln, ah_err_t err);
void s_client_on_connect(void* ctx_, ah_http_client_t* cln, ah_err_t err);
void s_client_on_send(void* ctx_, ah_http_client_t* cln, ah_http_head_t* head, ah_err_t err);
void s_client_on_recv_line(void* ctx_, ah_http_client_t* cln, const char* line, ah_http_ver_t version);
void s_client_on_recv_header(void* ctx_, ah_http_client_t* cln, ah_http_header_t header);
void s_client_on_recv_headers(void* ctx_, ah_http_client_t* cln);
void s_client_on_recv_chunk_line(void* ctx_, ah_http_client_t* cln, size_t size, const char* ext);
void s_client_on_recv_data(void* ctx_, ah_http_client_t* cln, ah_tcp_in_t* in);
void s_client_on_recv_end(void* ctx_, ah_http_client_t* cln, ah_err_t err);
void s_client_on_close(void* ctx_, ah_http_client_t* cln, ah_err_t err);

void s_server_on_open(void* ctx_, ah_http_server_t* srv, ah_err_t err);
void s_server_on_listen(void* ctx_, ah_http_server_t* srv, ah_err_t err);
void s_server_on_accept(void* ctx_, ah_http_server_t* srv, ah_http_client_t* cln, ah_http_client_obs_t* obs, ah_err_t err);
void s_server_on_close(void* ctx_, ah_http_server_t* srv, ah_err_t err);

static const ah_http_client_cbs_t s_client_cbs = {
    .on_open = s_client_on_open,
    .on_connect = s_client_on_connect,
    .on_close = s_client_on_close,
    .on_send = s_client_on_send,
    .on_recv_line = s_client_on_recv_line,
    .on_recv_header = s_client_on_recv_header,
    .on_recv_headers = s_client_on_recv_headers,
    .on_recv_chunk_line = s_client_on_recv_chunk_line,
    .on_recv_data = s_client_on_recv_data,
    .on_recv_end = s_client_on_recv_end,
};

static const ah_http_server_cbs_t s_server_cbs = {
    .on_open = s_server_on_open,
    .on_listen = s_server_on_listen,
    .on_accept = s_server_on_accept,
    .on_close = s_server_on_close,
};

void s_client_on_open(void* ctx_, ah_http_client_t* cln, ah_err_t err)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        if (cln != NULL) {
            err = ah_http_client_term(cln);
            (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        }
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL")) {
        return;
    }

    if (ctx->connect_to_this_raddr_on_open_if_port_is_not_zero.as_ip.port != 0u) {
        err = ah_http_client_connect(cln, &ctx->connect_to_this_raddr_on_open_if_port_is_not_zero);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            return;
        }
    }
}

void s_client_on_connect(void* ctx_, ah_http_client_t* cln, ah_err_t err)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_connect_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL")) {
        return;
    }

    *ctx->client_count += 1u;

    if (ctx->send_this_head_on_connect_if_not_null != NULL) {
        err = ah_http_client_send_head(cln, ctx->send_this_head_on_connect_if_not_null);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }
        err = ah_http_client_send_end(cln);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }
        ctx->sent_message_count += 1u;
    }

    return;

handle_failure:
    if (cln != NULL) {
        err = ah_http_client_close(cln);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

void s_client_on_send(void* ctx_, ah_http_client_t* cln, ah_http_head_t* head, ah_err_t err)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_send_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        if (cln != NULL) {
            err = ah_http_client_close(cln);
            (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        }
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, head != NULL, "head != NULL")) {
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL")) {
        return;
    }

    if (ctx->send_this_head_on_connect_if_not_null != NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, head->line, "GET /things/1234");
    }
    if (ctx->send_this_head_on_recv_end_if_not_null != NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, head->line, "200 OK");
    }
}

void s_client_on_recv_line(void* ctx_, ah_http_client_t* cln, const char* line, ah_http_ver_t version)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_recv_line_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.major, 1u);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, version.minor, 1u);
    (void) ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL");

    if (ctx->send_this_head_on_connect_if_not_null == NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "GET /things/1234");
    }
    if (ctx->send_this_head_on_recv_end_if_not_null == NULL) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, line, "200 OK");
    }
}

void s_client_on_recv_header(void* ctx_, ah_http_client_t* cln, ah_http_header_t header)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_recv_header_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert(AH_UNIT_CTX, res, header.name != NULL, "header.name != NULL");
    (void) ah_unit_assert(AH_UNIT_CTX, res, header.value != NULL, "header.value != NULL");
    (void) ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL");
}

void s_client_on_recv_headers(void* ctx_, ah_http_client_t* cln)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_recv_headers_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL");
}

void s_client_on_recv_chunk_line(void* ctx_, ah_http_client_t* cln, size_t size, const char* ext)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_recv_chunk_line_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) size;
    (void) ext;
    (void) ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL");
}

void s_client_on_recv_data(void* ctx_, ah_http_client_t* cln, ah_tcp_in_t* in)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_recv_data_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert(AH_UNIT_CTX, res, in != NULL, "in != NULL")) {
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL")) {
        return;
    }

    if (ctx->send_this_head_on_connect_if_not_null != NULL) {
        if (ah_rw_get_readable_size(&in->rw) < 28u) {
            return; // Wait for more data to arrive.
        }
        if (ah_unit_assert_eq_mem(AH_UNIT_CTX, res, in->rw.r, "{\"text\":\"Hello, Arrowhead!\"}", 28u)) {
            (void) ah_rw_skipn(&in->rw, 28u);
        }
        ctx->received_body_count += 1u;
    }
}

void s_client_on_recv_end(void* ctx_, ah_http_client_t* cln, ah_err_t err)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    if (err == AH_EEOF) {
        return;
    }
    ctx->on_recv_end_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL")) {
        return;
    }

    if (ctx->send_this_head_on_recv_end_if_not_null != NULL) {
        err = ah_http_client_send_head(cln, ctx->send_this_head_on_recv_end_if_not_null);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }
        if (ctx->send_this_out_on_recv_end_if_not_null != NULL) {
            err = ah_http_client_send_data(cln, ctx->send_this_out_on_recv_end_if_not_null);
            if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
                goto handle_failure;
            }
        }
        err = ah_http_client_send_end(cln);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }
        ctx->sent_message_count += 1u;
    }

    return;

handle_failure:
    if (cln != NULL) {
        err = ah_http_client_close(cln);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

void s_client_on_close(void* ctx_, ah_http_client_t* cln, ah_err_t err)
{
    struct s_client_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "cln != NULL")) {
        return;
    }

    ah_loop_t* loop = ah_http_client_get_loop(cln);
    (void) ah_unit_assert(AH_UNIT_CTX, res, loop != NULL, "loop != NULL");

    err = ah_http_client_term(cln);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    (*ctx->client_count) -= 1u;

    if (*ctx->client_count == 0u) {
        err = ah_loop_term(loop);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

void s_server_on_open(void* ctx_, ah_http_server_t* srv, ah_err_t err)
{
    struct s_server_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        if (srv != NULL) {
            err = ah_http_server_term(srv);
            (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        }
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, srv != NULL, "srv != NULL")) {
        return;
    }

    ah_tcp_listener_t* ln = ah_http_server_get_listener(srv);
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln == NULL")) {
        goto handle_failure;
    }

    err = ah_tcp_listener_set_nodelay(ln, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, ctx->res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_http_server_listen(srv, 1u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, ctx->res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (srv != NULL) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

void s_server_on_listen(void* ctx_, ah_http_server_t* srv, ah_err_t err)
{
    struct s_server_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_listen_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (err == AH_ECANCELED || !ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, srv != NULL, "srv != NULL")) {
        return;
    }

    // As we now have a server listening, we are ready to open the client that
    // will connect to it. For it to know where to connect, we give it the
    // address of the server before we open it.

    struct s_client_obs_ctx* client_obs_ctx = ah_http_client_get_obs_ctx(ctx->open_this_client_on_listen);
    if (!ah_unit_assert(AH_UNIT_CTX, res, client_obs_ctx != NULL, "client_obs_ctx != NULL")) {
        goto handle_failure;
    }

    ah_tcp_listener_t* ln = ah_http_server_get_listener(srv);
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln == NULL")) {
        goto handle_failure;
    }

    err = ah_tcp_listener_get_laddr(ln, &client_obs_ctx->connect_to_this_raddr_on_open_if_port_is_not_zero);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_http_client_open(ctx->open_this_client_on_listen, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (srv != NULL) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

void s_server_on_accept(void* ctx_, ah_http_server_t* srv, ah_http_client_t* cln, ah_http_client_obs_t* obs, ah_err_t err)
{
    struct s_server_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);

    ah_unit_res_t* res = ctx->res;

    // Normally, `obs` is guaranteed to be non-NULL. However, as this is a test
    // that the guarantee actually holds, we have to check for it anyway.
    if (obs != NULL) {
        obs->cbs = &s_client_cbs;
        obs->ctx = &ctx->accepted_client_obs_ctx;
    }

    if (err == AH_ECANCELED) {
        goto handle_failure;
    }

    ctx->on_accept_count += 1u;

    struct s_client_obs_ctx* cln_obs_ctx;

    // Also `cln` is guaranteed to be non-NULL, but we test it anyway just as
    // above.
    if (cln != NULL) {
        cln_obs_ctx = ah_http_client_get_obs_ctx(cln);
        if (cln_obs_ctx != NULL) {
            *cln_obs_ctx->client_count += 1u;
        }
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, obs != NULL, "obs != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln != NULL, "client != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, srv != NULL, "srv != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, cln_obs_ctx != NULL, "cln_obs_ctx != NULL")) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (cln != NULL) {
        err = ah_http_client_close(cln);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
    if (srv != NULL) {
        err = ah_http_server_close(srv);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

void s_server_on_close(void* ctx_, ah_http_server_t* srv, ah_err_t err)
{
    struct s_server_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, srv != NULL, "srv != NULL")) {
        return;
    }

    err = ah_http_server_term(srv);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
}

static void s_should_send_and_receive_short_message(ah_unit_res_t* res)
{
    ah_err_t err;

    // Setup event loop.
    ah_loop_t loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // We increment this for each connected/accepted client, and decrement if
    // for every closed client. When it transitions from 1 to 0, we terminate
    // `loop`.
    size_t client_count = 0u;

    // Get plain TCP transport.
    ah_tcp_trans_t transport = ah_tcp_trans_get_root();

    // Setup HTTP server.
    struct s_server_obs_ctx server_obs_ctx = {
        .accepted_client_obs_ctx = (struct s_client_obs_ctx) {
            .send_this_head_on_recv_end_if_not_null = &(ah_http_head_t) {
                .line = "200 OK",
                .version = { 1u, 1u },
                .headers = (ah_http_header_t[]) {
                    { "content-length", "28" },
                    { "content-type", "application/json" },
                    { "user-agent", "Arrowhead Core C" },
                    { NULL, NULL },
                },
            },
            .send_this_out_on_recv_end_if_not_null = &(ah_tcp_out_t) {
                .buf = ah_buf_from((uint8_t*) "{\"text\":\"Hello, Arrowhead!\"}", 28u),
            },
            .client_count = &client_count,
            .res = res,
        },
        .res = res,
    };
    ah_http_server_t server;
    err = ah_http_server_init(&server, &loop, transport, (ah_http_server_obs_t) { &s_server_cbs, &server_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup local HTTP client.
    struct s_client_obs_ctx lclient_obs_ctx = {
        .send_this_head_on_connect_if_not_null = &(ah_http_head_t) {
            .line = "GET /things/1234",
            .version = { 1u, 1u },
            .headers = (ah_http_header_t[]) {
                { "accept", "application/json" },
                { "connection", "close" },
                { "content-length", "0" },
                { NULL, NULL }, // "host" header is added automatically.
            },
        },
        .client_count = &client_count,
        .res = res,
    };
    ah_http_client_t lclient;
    err = ah_http_client_init(&lclient, &loop, transport, (ah_http_client_obs_t) { &s_client_cbs, &lclient_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // The server keeps a reference to `client` for us to be able to open it
    // after `server` is ready to accept connecting clients.
    server_obs_ctx.open_this_client_on_listen = &lclient;

    // Open HTTP server.
    err = ah_http_server_open(&server, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Execute event loop.
    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 1 * AH_TIMEDIFF_S, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Check results after event loop stops executing.

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_open_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_connect_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_send_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_recv_line_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_recv_header_count, 3u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_recv_headers_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_recv_chunk_line_count, 0u);
    (void) ah_unit_assert(AH_UNIT_CTX, res, lclient_obs_ctx.on_recv_data_count > 0u, "lclient_obs_ctx.on_recv_data_count > 0u");
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_recv_end_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.on_close_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.received_body_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lclient_obs_ctx.sent_message_count, 1u);

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, server_obs_ctx.on_open_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, server_obs_ctx.on_listen_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, server_obs_ctx.on_accept_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, server_obs_ctx.on_close_count, 1u);

    struct s_client_obs_ctx* rclient_obs_ctx = &server_obs_ctx.accepted_client_obs_ctx;
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_open_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_connect_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_send_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_recv_line_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_recv_header_count, 4u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_recv_headers_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_recv_chunk_line_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_recv_data_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_recv_end_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->received_body_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->sent_message_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rclient_obs_ctx->on_close_count, 1u);

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}
