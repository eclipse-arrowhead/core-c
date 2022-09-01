// SPDX-License-Identifier: EPL-2.0

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/tcp.h"

#include <ah/unit.h>

struct s_conn_obs_ctx {
    ah_sockaddr_t connect_to_this_addr_on_open;

    size_t* conn_close_countdown;

    size_t on_open_count;
    size_t on_connect_count;
    size_t on_read_count;
    size_t on_write_count;
    size_t on_close_count;
    size_t received_message_count;

    ah_unit_res_t* res;
};

struct s_listener_obs_ctx {
    ah_tcp_conn_t* open_this_conn_on_listen;

    struct s_conn_obs_ctx rconn_obs_ctx;
    ah_tcp_out_t rconn_out;

    size_t on_open_count;
    size_t on_listen_count;
    size_t on_accept_count;
    size_t on_close_count;

    ah_unit_res_t* res;
};

static void s_should_read_and_write_data(ah_unit_res_t* res);

void test_tcp(ah_unit_res_t* res)
{
    s_should_read_and_write_data(res);
}

static void s_conn_on_open(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_connect(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err);
static void s_conn_on_read(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_conn_on_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_conn_on_close(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err);

static void s_listener_on_open(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_listen(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err);
static void s_listener_on_accept(void* ctx_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t* obs, const ah_sockaddr_t* raddr, ah_err_t err);
static void s_listener_on_close(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err);

static const ah_tcp_conn_cbs_t s_conn_cbs = {
    .on_open = s_conn_on_open,
    .on_connect = s_conn_on_connect,
    .on_read = s_conn_on_read,
    .on_write = s_conn_on_write,
    .on_close = s_conn_on_close,
};

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = s_listener_on_open,
    .on_listen = s_listener_on_listen,
    .on_accept = s_listener_on_accept,
    .on_close = s_listener_on_close,
};

// This function is not called for our accepted connection.
static void s_conn_on_open(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        ah_tcp_conn_term(conn);
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    err = ah_tcp_conn_set_keepalive(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_conn_set_nodelay(conn, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_conn_set_reuseaddr(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_conn_connect(conn, &ctx->connect_to_this_addr_on_open);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

// This function is not called for our accepted connection.
static void s_conn_on_connect(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_connect_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

#if AH_IS_WIN32
# pragma warning(disable : 6011)
#endif

static void s_conn_on_read(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_read_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, in != NULL, "in != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    if (ah_rw_get_readable_size(&in->rw) < 18u) {
        return; // Wait until there is more data to read.
    }

    if (!ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_rw_get_readable_size(&in->rw), 18u)) {
        goto handle_failure;
    }

    if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, (char*) in->rw.r, "Hello, Arrowhead!")) {
        goto handle_failure;
    }

    ah_rw_skipn(&in->rw, 18u);
    ctx->received_message_count += 1u;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

#if AH_IS_WIN32
# pragma warning(default : 6011)
#endif

static void s_conn_on_write(void* ctx_, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_write_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    (void) ah_unit_assert(AH_UNIT_CTX, res, out != NULL, "out != NULL");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL");

    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_conn_on_close(void* ctx_, ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_conn_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        return;
    }

    ah_loop_t* loop = ah_tcp_conn_get_loop(conn);
    (void) ah_unit_assert(AH_UNIT_CTX, res, loop != NULL, "loop != NULL");

    err = ah_tcp_conn_term(conn);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    (*ctx->conn_close_countdown) -= 1u;

    if (*ctx->conn_close_countdown == 0u) {
        err = ah_loop_term(loop);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_listener_on_open(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        if (ln != NULL) {
            ah_tcp_listener_term(ln);
        }
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    err = ah_tcp_listener_listen(ln, 1u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    ah_tcp_listener_close(ln);
}

static void s_listener_on_listen(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_listen_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        return;
    }

    // As we now have a listener listening, we are ready to open the connection
    // that will connect to it. For it to know where to connect, we give it the
    // address of the listener before we open it.

    struct s_conn_obs_ctx* conn_obs_ctx = ah_tcp_conn_get_obs_ctx(ctx->open_this_conn_on_listen);
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn_obs_ctx != NULL, "conn_obs_ctx != NULL")) {
        goto handle_failure;
    }

    err = ah_tcp_listener_get_laddr(ln, &conn_obs_ctx->connect_to_this_addr_on_open);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    err = ah_tcp_conn_open(ctx->open_this_conn_on_listen, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (ln != NULL) {
        (void) ah_tcp_listener_close(ln);
    }
}

static void s_listener_on_accept(void* ctx_, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, ah_tcp_conn_obs_t* obs, const ah_sockaddr_t* raddr, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_accept_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (err == AH_ECANCELED) {
        goto handle_failure;
    }
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, raddr != NULL, "raddr != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, obs != NULL, "obs != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, conn != NULL, "conn != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        goto handle_failure;
    }

    obs->cbs = &s_conn_cbs;
    obs->ctx = &ctx->rconn_obs_ctx;

    err = ah_buf_init(&ctx->rconn_out.buf, (uint8_t*) "Hello, Arrowhead!", 18u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    err = ah_tcp_conn_write(conn, &ctx->rconn_out);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    // We are done accepting connections now.
    err = ah_tcp_listener_close(ln);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    return;

handle_failure:
    if (conn != NULL) {
        err = ah_tcp_conn_close(conn);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
    if (ln != NULL) {
        err = ah_tcp_listener_close(ln);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_listener_on_close(void* ctx_, ah_tcp_listener_t* ln, ah_err_t err)
{
    struct s_listener_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, ln != NULL, "ln != NULL")) {
        return;
    }

    err = ah_tcp_listener_term(ln);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
}

static void s_should_read_and_write_data(ah_unit_res_t* res)
{
    ah_err_t err;

    // Setup event loop.
    ah_loop_t loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // When this number of connections have been closed, we terminate the event loop.
    size_t conn_close_countdown = 2u;

    // Setup listener.
    struct s_listener_obs_ctx ln_obs_ctx = {
        .rconn_obs_ctx = (struct s_conn_obs_ctx) {
            .conn_close_countdown = &conn_close_countdown,
            .res = res,
        },
        .res = res,
    };
    ah_tcp_listener_t ln;
    err = ah_tcp_listener_init(&ln, &loop, ah_tcp_trans_get_root(), (ah_tcp_listener_obs_t) { &s_listener_cbs, &ln_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup local connection.
    struct s_conn_obs_ctx lconn_obs_ctx = {
        .conn_close_countdown = &conn_close_countdown,
        .res = res,
    };
    ah_tcp_conn_t lconn;
    err = ah_tcp_conn_init(&lconn, &loop, ah_tcp_trans_get_root(), (ah_tcp_conn_obs_t) { &s_conn_cbs, &lconn_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // The listener keeps a reference to `conn` for us to be able to open it
    // after `ln` is ready to accept incoming connections.
    ln_obs_ctx.open_this_conn_on_listen = &lconn;

    // Open listener.
    err = ah_tcp_listener_open(&ln, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
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

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_open_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_connect_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_close_count, 1u);
    (void) ah_unit_assert(AH_UNIT_CTX, res, lconn_obs_ctx.on_read_count > 0u, "lconn_obs_ctx.on_read_count > 0u");
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.on_write_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, lconn_obs_ctx.received_message_count, 1u);

    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_open_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_listen_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_close_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ln_obs_ctx.on_accept_count, 1u);

    struct s_conn_obs_ctx* rconn_obs_ctx = &ln_obs_ctx.rconn_obs_ctx;
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_open_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_connect_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_close_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_read_count, 0u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->on_write_count, 1u);
    (void) ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, rconn_obs_ctx->received_message_count, 0u);

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}
