// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/tcp.h"

#include <ah/unit.h>

struct s_tcp_conn_user_data {
    const ah_sockaddr_t* ln_addr;
    ah_tcp_listener_t* ln;

    size_t* close_call_counter;

    bool did_call_open_cb;
    bool did_call_connect_cb;
    bool did_call_read_cb;
    bool did_call_write_cb;
    bool did_call_close_cb;

    ah_unit_res_t* res;
};

struct s_tcp_listener_user_data {
    ah_sockaddr_t addr;
    ah_tcp_conn_t* conn;

    struct s_tcp_conn_user_data accept_user_data;
    ah_tcp_out_t conn_msg;

    bool did_call_open_cb;
    bool did_call_listen_cb;
    bool did_call_accept_cb;
    bool did_call_close_cb;

    ah_unit_res_t* res;
};

static void s_should_read_and_write_data(ah_unit_res_t* res);

void test_tcp(ah_unit_res_t* res)
{
    s_should_read_and_write_data(res);
}

static void s_on_conn_open(void* ctx, ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_connect(void* ctx, ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_read(void* ctx, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err);
static void s_on_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err);
static void s_on_conn_close(void* ctx, ah_tcp_conn_t* conn, ah_err_t err);

static void s_on_listener_open(void* ctx, ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_listen(void* ctx, ah_tcp_listener_t* ln, ah_err_t err);
static void s_on_listener_accept(void* ctx, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err);
static void s_on_listener_close(void* ctx, ah_tcp_listener_t* ln, ah_err_t err);

static const ah_tcp_conn_cbs_t s_conn_cbs = {
    .on_open = s_on_conn_open,
    .on_connect = s_on_conn_connect,
    .on_read = s_on_conn_read,
    .on_write = s_on_conn_write,
    .on_close = s_on_conn_close,
};

static const ah_tcp_listener_cbs_t s_listener_cbs = {
    .on_open = s_on_listener_open,
    .on_listen = s_on_listener_listen,
    .on_accept = s_on_listener_accept,
    .on_close = s_on_listener_close,
};

static void s_on_conn_open(void* ctx, ah_tcp_conn_t* conn, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_set_keepalive(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_set_nodelay(conn, true);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_set_reuseaddr(conn, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_connect(conn, user_data->ln_addr);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void s_on_conn_connect(void* ctx, ah_tcp_conn_t* conn, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        (void) ah_tcp_conn_close(conn);
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_connect_cb = true;
}

static void s_on_conn_close(void* ctx, ah_tcp_conn_t* conn, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    (*user_data->close_call_counter) += 1u;

    if (*user_data->close_call_counter == 2u) {
        ah_loop_t* loop = ah_tcp_conn_get_loop(conn);
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

#if AH_IS_WIN32
# pragma warning(disable : 6011)
#endif

static void s_on_conn_read(void* ctx, ah_tcp_conn_t* conn, ah_tcp_in_t* in, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        (void) ah_tcp_conn_close(conn);
        return;
    }

    if (!ah_unit_assert(AH_UNIT_CTX, res, in != NULL, "in == NULL")) {
        return;
    }

    if (!ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, ah_rw_get_readable_size(&in->rw), 18u)) {
        return;
    }

    if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, (char*) in->rw.r, "Hello, Arrowhead!")) {
        return;
    }

    // If we do not read everything in the input buffer, its current contents
    // will be preserved until more data becomes available.
    ah_rw_skip_all(&in->rw);

    ah_err_t err0 = ah_tcp_conn_close(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err0, AH_ENONE)) {
        return;
    }

    user_data->did_call_read_cb = true;
}

#if AH_IS_WIN32
# pragma warning(default : 6011)
#endif

static void s_on_conn_write(void* ctx, ah_tcp_conn_t* conn, ah_tcp_out_t* out, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        (void) ah_tcp_conn_close(conn);
        return;
    }

    if (!ah_unit_assert(AH_UNIT_CTX, res, out != NULL, "out == NULL")) {
        return;
    }

    err = ah_tcp_conn_close(conn);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_listener_close(user_data->ln);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_write_cb = true;
}

static void s_on_listener_open(void* ctx, ah_tcp_listener_t* ln, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        (void) ah_tcp_listener_close(ln);
        return;
    }

    err = ah_tcp_listener_set_nodelay(ln, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_listener_listen(ln, 1, (ah_tcp_conn_obs_t) { &s_conn_cbs });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void s_on_listener_listen(void* ctx, ah_tcp_listener_t* ln, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);
    ah_unit_res_t* res = user_data->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        (void) ah_tcp_listener_close(ln);
        return;
    }

    // Save the IP address the listener is bound to.
    err = ah_tcp_listener_get_laddr(ln, &user_data->addr);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Open connection that will connect to our listener.
    err = ah_tcp_conn_open(user_data->conn, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_listen_cb = true;
}

static void s_on_listener_close(void* ctx, ah_tcp_listener_t* ln, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, user_data->res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_close_cb = true;
}

static void s_on_listener_accept(void* ctx, ah_tcp_listener_t* ln, ah_tcp_conn_t* conn, const ah_sockaddr_t* raddr, ah_err_t err)
{
    (void) ctx;

    struct s_tcp_listener_user_data* user_data = ah_tcp_listener_get_user_data(ln);

    ah_unit_res_t* res = user_data->res;

    if (err == AH_ECANCELED) {
        return;
    }

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ah_unit_assert(AH_UNIT_CTX, res, raddr != NULL, "raddr == NULL");

    ah_tcp_conn_set_user_data(conn, &user_data->accept_user_data);

    err = ah_buf_init(&user_data->conn_msg.buf, (uint8_t*) "Hello, Arrowhead!", 18u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    err = ah_tcp_conn_write(conn, &user_data->conn_msg);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    user_data->did_call_accept_cb = true;
}

static void s_should_read_and_write_data(ah_unit_res_t* res)
{
    ah_err_t err;

    // Setup user data.

    size_t close_call_counter = 0u;

    struct s_tcp_conn_user_data conn_user_data = {
        .close_call_counter = &close_call_counter,
        .res = res,
    };

    struct s_tcp_listener_user_data ln_user_data = {
        .accept_user_data = (struct s_tcp_conn_user_data) {
            .close_call_counter = &close_call_counter,
            .res = res,
        },
        .res = res,
    };

    // Setup event loop.

    ah_loop_t loop;

    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup listener.

    ah_tcp_listener_t ln;
    err = ah_tcp_listener_init(&ln, &loop, ah_tcp_trans_get_default(), (ah_tcp_listener_obs_t) { &s_listener_cbs });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    ln_user_data.accept_user_data.ln = &ln;
    ah_tcp_listener_set_user_data(&ln, &ln_user_data);

    // Setup connection.

    ah_tcp_conn_t conn;
    err = ah_tcp_conn_init(&conn, &loop, ah_tcp_trans_get_default(), (ah_tcp_conn_obs_t) { &s_conn_cbs });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    conn_user_data.ln_addr = &ln_user_data.addr;
    ah_tcp_conn_set_user_data(&conn, &conn_user_data);

    ln_user_data.conn = &conn;

    // Open listener, which will open the connection, and so on.

    err = ah_tcp_listener_open(&ln, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
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

    // Check results.

    struct s_tcp_conn_user_data* conn_data = &conn_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_open_cb, "`conn` s_on_conn_open() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_connect_cb, "`conn` s_on_conn_connect() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_close_cb, "`conn` s_on_conn_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, conn_data->did_call_read_cb, "`conn` s_on_conn_read() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !conn_data->did_call_write_cb, "`conn` s_on_conn_write() was called");

    struct s_tcp_listener_user_data* ln_data = &ln_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_open_cb, "`ln` s_on_listener_open() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_listen_cb, "`ln` s_on_listener_listen() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_close_cb, "`ln` s_on_listener_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, ln_data->did_call_accept_cb, "`ln` s_on_listener_accept() not called");

    struct s_tcp_conn_user_data* acc_data = &ln_data->accept_user_data;
    (void) ah_unit_assert(AH_UNIT_CTX, res, !acc_data->did_call_open_cb, "`acc` s_on_conn_open() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !acc_data->did_call_connect_cb, "`acc` s_on_conn_connect() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, acc_data->did_call_close_cb, "`acc` s_on_conn_close() not called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, !acc_data->did_call_read_cb, "`acc` s_on_conn_read() was called");
    (void) ah_unit_assert(AH_UNIT_CTX, res, acc_data->did_call_write_cb, "`acc` s_on_conn_write() not called");

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}
