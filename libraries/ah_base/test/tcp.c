// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/err.h"
#include "ah/ip.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/unit.h"

struct s_tcp_conn_user_data {
    ah_buf_t* free_buf;
    ah_buf_t* write_buf;

    const ah_sockaddr_t* remote_addr;

    bool did_call_open_cb;
    bool did_call_connect_cb;
    bool did_call_close_cb;
    bool did_call_read_alloc_cb;
    bool did_call_read_done_cb;
    bool did_call_write_done_cb;

    ah_unit_t* unit;
};

struct s_tcp_listener_user_data {
    ah_buf_t* free_buf;

    ah_unit_t* unit;
};

static void s_should_read_and_write_data(ah_unit_t* unit);

void test_tcp(ah_unit_t* unit)
{
    s_should_read_and_write_data(unit);
}

static void s_on_conn_a_open(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_a_connect(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_a_close(ah_tcp_conn_t* conn, ah_err_t err);
static void s_on_conn_a_read_alloc(ah_tcp_conn_t* conn, ah_bufs_t* bufs, size_t n_bytes_expected);
static void s_on_conn_a_read_done(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_read, ah_err_t err);
static void s_on_conn_a_write_done(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_written, ah_err_t err);

static const ah_tcp_conn_vtab_t s_conn_a_vtab = {
    .on_open = s_on_conn_a_open,
    .on_connect = s_on_conn_a_connect,
    .on_close = s_on_conn_a_close,
    .on_read_alloc = s_on_conn_a_read_alloc,
    .on_read_done = s_on_conn_a_read_done,
    .on_write_done = s_on_conn_a_write_done,
};

static void s_on_conn_a_open(ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_set_keepalive(conn, false);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_set_nodelay(conn, true);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_set_reuseaddr(conn, false);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_connect(conn, user_data->remote_addr);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void s_on_conn_a_connect(ah_tcp_conn_t* conn, ah_err_t err)
{
    struct s_tcp_conn_user_data* user_data = ah_tcp_conn_get_user_data(conn);

    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_tcp_conn_read_start(conn);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_connect_cb = true;
}

static void s_on_conn_a_close(ah_tcp_conn_t* conn, ah_err_t err)
{

}

static void s_on_conn_a_read_alloc(ah_tcp_conn_t* conn, ah_bufs_t* bufs, size_t n_bytes_expected)
{

}

static void s_on_conn_a_read_done(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_read, ah_err_t err)
{

}

static void s_on_conn_a_write_done(ah_tcp_conn_t* conn, ah_bufs_t bufs, size_t n_bytes_written, ah_err_t err)
{

}






static void s_on_alloc_mem(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t size);
static void s_on_read(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t size, ah_err_t err);
static void s_on_write(ah_tcp_sock_t* sock, ah_err_t err);

static void s_on_accept(ah_tcp_sock_t* sock, ah_tcp_sock_t* conn, const ah_sockaddr_t* remote_addr, ah_err_t err)
{
    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    if (!ah_unit_assert(unit, conn != NULL, "conn == NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, remote_addr != NULL, "remote_addr == NULL")) {
        return;
    }

    ah_tcp_set_user_data(conn, user_data);

    if (!ah_unit_assert(unit, user_data->free_read_ctx != NULL, "data->free_read_ctx == NULL")) {
        return;
    }
    ah_tcp_read_ctx_t* read_ctx = user_data->free_read_ctx;
    user_data->free_read_ctx = NULL;

    *read_ctx = (ah_tcp_read_ctx_t) {
        .alloc_cb = s_on_alloc_mem,
        .read_cb = s_on_read,
    };

    ah_err_t err0 = ah_tcp_read_start(conn, read_ctx);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err0)) {
        return;
    }

    user_data->_did_accept = true;
}

static void s_on_alloc_mem(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t size)
{
    (void) size;

    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert(unit, bufs != NULL, "bufs == NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, bufs->items == NULL, "bufs->items != NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, user_data->free_read_buf != NULL, "data->free_read_buf == NULL")) {
        return;
    }

    bufs->items = user_data->free_read_buf;
    bufs->length = 1u;

    user_data->free_read_buf = NULL;
    user_data->_did_alloc_mem = true;
}

static void s_on_alloc_sock(ah_tcp_sock_t* sock, ah_tcp_sock_t** conn)
{
    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert(unit, conn != NULL, "conn == NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, *conn == NULL, "*conn != NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, user_data->free_read_conn != NULL, "data->free_read_conn == NULL")) {
        return;
    }

    *conn = user_data->free_read_conn;
    user_data->free_read_conn = NULL;

    user_data->_did_alloc_sock = true;
}

static void s_on_connect(ah_tcp_sock_t* conn, ah_err_t err)
{
    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(conn);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (!ah_unit_assert(unit, user_data->free_write_buf != NULL, "data->free_write_buf == NULL")) {
        return;
    }
    ah_buf_t* write_buf = user_data->free_write_buf;
    user_data->free_write_buf = NULL;

    *write_buf = (ah_buf_t) {
        ._octets = (uint8_t*) "Hello, Arrowhead!",
        ._size = 18u,
    };

    if (!ah_unit_assert(unit, user_data->free_write_ctx != NULL, "data->free_write_ctx == NULL")) {
        return;
    }
    ah_tcp_write_ctx_t* write_ctx = user_data->free_write_ctx;
    user_data->free_write_ctx = NULL;

    *write_ctx = (ah_tcp_write_ctx_t) {
        .bufs = (ah_bufs_t) {
            .items = write_buf,
            .length = 1u,
        },
        .write_cb = s_on_write,
    };

    ah_err_t err0 = ah_tcp_write(conn, write_ctx);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err0)) {
        return;
    }

    user_data->_did_connect = true;
}

static void s_on_listen(ah_tcp_sock_t* sock, ah_err_t err)
{
    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->_did_listen = true;
}

static void s_on_read(ah_tcp_sock_t* sock, ah_bufs_t* bufs, size_t size, ah_err_t err)
{
    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_unit_assert(unit, bufs != NULL, "bufs == NULL");

    if (!ah_unit_assert_unsigned_eq(unit, 18u, size)) {
        return;
    }
    if (!ah_unit_assert_unsigned_eq(unit, 1u, bufs->length)) {
        return;
    }
    if (!ah_unit_assert(unit, bufs->items != NULL, "bufs->items == NULL")) {
        return;
    }
    if (!ah_unit_assert_cstr_eq(unit, "Hello, Arrowhead!", (char*) bufs->items[0]._octets)) {
        return;
    }

    ah_err_t err0 = ah_tcp_close(sock, NULL);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err0)) {
        return;
    }

    // Free bufs.
    user_data->free_read_buf = bufs->items;
    bufs->items = NULL;
    bufs->length = 0u;

    user_data->_did_read = true;
}

static void s_on_write(ah_tcp_sock_t* sock, ah_err_t err)
{
    struct s_tcp_user_data* user_data = ah_tcp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->_did_write = true;
}

static void s_should_read_and_write_data(ah_unit_t* unit)
{
    ah_err_t err;

    // Setup user data.

    uint8_t read_buf_octets[24] = { 0u };

    struct s_tcp_user_data user_data = {
        .free_read_buf = &(ah_buf_t) {
            ._octets = read_buf_octets,
            ._size = sizeof(read_buf_octets),
        },
        .free_read_conn = &(ah_tcp_sock_t) { 0 },
        .free_read_ctx = &(ah_tcp_read_ctx_t) { 0 },
        .free_write_buf = &(ah_buf_t) { 0 },
        .free_write_ctx = &(ah_tcp_write_ctx_t) { 0 },
        .unit = unit,
    };

    // Setup reader.

    ah_loop_t read_loop;
    ah_tcp_conn_t read_conn;
    ah_sockaddr_t read_addr;

    err = ah_loop_init(&read_loop, &(ah_loop_opts_t) { .capacity = 4u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_sockaddr_init_ipv4(&read_addr, 0u, &ah_ipaddr_v4_loopback);

    ah_tcp_conn_init(&read_conn, &read_loop, );
    err = ah_tcp_open(&read_conn, &read_addr, NULL);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    ah_tcp_set_user_data(&read_conn, &user_data);

    err = ah_tcp_get_local_addr(&read_conn, &read_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Listen for writer connection.

    err = ah_tcp_listen(&read_conn, 4,
        &(ah_tcp_listen_ctx_t) {
            .alloc_cb = s_on_alloc_sock,
            .listen_cb = s_on_listen,
            .accept_cb = s_on_accept,
        });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Setup writer.

    ah_loop_t write_loop;
    ah_tcp_sock_t write_sock;
    ah_sockaddr_t write_addr;

    err = ah_loop_init(&write_loop, &(ah_loop_opts_t) { .capacity = 4u });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_sockaddr_init_ipv4(&write_addr, 0u, &ah_ipaddr_v4_loopback);

    ah_tcp_init(&write_sock, &write_loop);
    err = ah_tcp_open(&write_sock, &write_addr, NULL);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    ah_tcp_set_user_data(&write_sock, &user_data);

    // Connect writer to reader.

    err = ah_tcp_connect(&write_sock, &read_addr, s_on_connect);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Submit.

    ah_time_t deadline;

    err = ah_time_add(ah_time_now(), 10 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    err = ah_loop_run_until(&write_loop, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_time_add(ah_time_now(), 10 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    err = ah_loop_run_until(&read_loop, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Check results.

    ah_unit_assert(unit, user_data._did_accept, "reader did not accept writer connection");
    ah_unit_assert(unit, user_data._did_alloc_mem, "reader did not allocate memory for message");
    ah_unit_assert(unit, user_data._did_alloc_sock, "listener did not allocate memory for incoming connection");
    ah_unit_assert(unit, user_data._did_connect, "writer connect callback never invoked");
    ah_unit_assert(unit, user_data._did_listen, "reader listen callback never invoked");
    ah_unit_assert(unit, user_data._did_read, "reader did not receive sent message");
    ah_unit_assert(unit, user_data._did_write, "writer write callback never invoked");

    // Release all resources.

    err = ah_tcp_close(&read_conn, NULL);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);

    err = ah_loop_term(&read_loop);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);

    err = ah_tcp_close(&write_sock, NULL);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);

    err = ah_loop_term(&write_loop);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);
}
