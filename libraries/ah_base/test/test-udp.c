// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/ip.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/udp.h"
#include "ah/unit.h"

#if AH_IS_WIN32
# include <ws2ipdef.h>
#endif

static void s_should_send_and_receive_data(ah_unit_t* unit);
#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(ah_unit_t* unit);
#endif

void test_udp(ah_unit_t* unit)
{
    s_should_send_and_receive_data(unit);
#if AH_HAS_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_mreq(unit);
#endif
}

struct s_udp_sock_user_data {
    ah_buf_t* free_buf;

    ah_udp_msg_t* send_msg;

    size_t* close_call_counter;

    bool did_call_open_cb;
    bool did_call_close_cb;
    bool did_call_recv_alloc_cb;
    bool did_call_recv_done_cb;
    bool did_call_send_done_cb;

    ah_unit_t* unit;
};

static void s_on_open(ah_udp_sock_t* sock, ah_err_t err);
static void s_on_close(ah_udp_sock_t* sock, ah_err_t err);
static void s_on_recv_alloc(ah_udp_sock_t* sock, ah_buf_t* buf);
static void s_on_recv_data(ah_udp_sock_t* sock, const ah_buf_t* buf, size_t nrecv, const ah_sockaddr_t* raddr);
static void s_on_recv_err(ah_udp_sock_t* sock, const ah_sockaddr_t* raddr, ah_err_t err);
static void s_on_send_done(ah_udp_sock_t* sock, size_t nsent, const ah_sockaddr_t* raddr, ah_err_t err);

static const ah_udp_sock_vtab_t s_sock_vtab = {
    .on_open = s_on_open,
    .on_close = s_on_close,
    .on_recv_alloc = s_on_recv_alloc,
    .on_recv_data = s_on_recv_data,
    .on_recv_err = s_on_recv_err,
    .on_send_done = s_on_send_done,
};

static void s_on_open(ah_udp_sock_t* sock, ah_err_t err)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);

    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    err = ah_udp_sock_set_reuseaddr(sock, false);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    if (user_data->send_msg != NULL) {
        err = ah_udp_sock_send(sock, user_data->send_msg);
    }
    else {
        err = ah_udp_sock_recv_start(sock);
    }

    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_open_cb = true;
}

static void s_on_close(ah_udp_sock_t* sock, ah_err_t err)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    (*user_data->close_call_counter) += 1u;

    if (*user_data->close_call_counter == 2u) {
        ah_loop_t* loop = ah_udp_sock_get_loop(sock);
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

static void s_on_recv_alloc(ah_udp_sock_t* sock, ah_buf_t* buf)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    ah_unit_t* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert(unit, buf != NULL, "bufs == NULL")) {
        return;
    }

    *buf = *user_data->free_buf;
    user_data->free_buf = NULL;

    user_data->did_call_recv_alloc_cb = true;
}

static void s_on_recv_data(ah_udp_sock_t* sock, const ah_buf_t* buf, size_t nrecv, const ah_sockaddr_t* raddr)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert(unit, buf != NULL, "buf == NULL")) {
        return;
    }

    if (!ah_unit_assert_unsigned_eq(unit, 18u, nrecv)) {
        return;
    }

    if (!ah_unit_assert_unsigned_eq(unit, 24u, ah_buf_get_size(buf))) {
        return;
    }
    if (!ah_unit_assert_cstr_eq(unit, "Hello, Arrowhead!", (char*) ah_buf_get_base_const(buf))) {
        return;
    }

    if (!ah_unit_assert(unit, raddr != NULL, "raddr == NULL")) {
        return;
    }

    ah_err_t err = ah_udp_sock_close(sock);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_recv_done_cb = true;
}

static void s_on_recv_err(ah_udp_sock_t* sock, const ah_sockaddr_t* raddr, ah_err_t err)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);
    ah_unit_failf(user_data->unit, "unexpected recv error: %d [%s]", err, ah_strerror(err));
    (void) raddr;
}

static void s_on_send_done(ah_udp_sock_t* sock, size_t nsent, const ah_sockaddr_t* raddr, ah_err_t err)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);
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

    if (!ah_unit_assert_unsigned_eq(unit, 18u, nsent)) {
        return;
    }

    if (!ah_unit_assert(unit, raddr != NULL, "raddr == NULL")) {
        return;
    }

    err = ah_udp_sock_close(sock);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_send_done_cb = true;
}

static void s_should_send_and_receive_data(ah_unit_t* unit)
{
    ah_err_t err;

    // Setup event loop.

    ah_loop_t loop;
    err = ah_loop_init(&loop, &(ah_loop_opts_t) { .capacity = 4 });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Setup close counter, which we use to decide when to terminate `loop`.
    size_t close_call_counter = 0u;

    // Setup and open receiver socket.

    uint8_t free_buf_base[24] = { 0u };
    ah_buf_t free_buf;
    err = ah_buf_init(&free_buf, free_buf_base, sizeof(free_buf_base));
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    struct s_udp_sock_user_data recv_sock_user_data = {
        .free_buf = &free_buf,
        .close_call_counter = &close_call_counter,
        .unit = unit,
    };

    ah_udp_sock_t recv_sock;
    ah_sockaddr_t recv_addr;

    ah_sockaddr_init_ipv4(&recv_addr, 0u, &ah_ipaddr_v4_loopback);

    err = ah_udp_sock_init(&recv_sock, &loop, &s_sock_vtab);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_udp_sock_set_user_data(&recv_sock, &recv_sock_user_data);

    err = ah_udp_sock_open(&recv_sock, &recv_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_udp_sock_get_laddr(&recv_sock, &recv_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Setup and open sender socket.

    ah_buf_t send_buf;
    ah_buf_init(&send_buf, (uint8_t*) "Hello, Arrowhead!", 18u);

    ah_bufs_t send_bufs = { .items = &send_buf, .length = 1u };

    ah_udp_msg_t send_msg;
    ah_udp_msg_init(&send_msg, send_bufs, &recv_addr);

    struct s_udp_sock_user_data send_sock_user_data = {
        .send_msg = &send_msg,
        .close_call_counter = &close_call_counter,
        .unit = unit,
    };

    ah_udp_sock_t send_sock;
    ah_sockaddr_t send_addr;

    ah_sockaddr_init_ipv4(&send_addr, 0u, &ah_ipaddr_v4_loopback);

    err = ah_udp_sock_init(&send_sock, &loop, &s_sock_vtab);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_udp_sock_set_user_data(&send_sock, &send_sock_user_data);

    err = ah_udp_sock_open(&send_sock, &send_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Submit issued events for execution.

    struct ah_time deadline;
    err = ah_time_add(ah_time_now(), 1000 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Check results.

    struct s_udp_sock_user_data* recv_data = &recv_sock_user_data;
    ah_unit_assert(unit, recv_data->did_call_open_cb, "`recv` s_on_sock_open() not called");
    ah_unit_assert(unit, recv_data->did_call_close_cb, "`recv` s_on_sock_close() not called");
    ah_unit_assert(unit, recv_data->did_call_recv_alloc_cb, "`recv` s_on_sock_recv_alloc() not called");
    ah_unit_assert(unit, recv_data->did_call_recv_done_cb, "`recv` s_on_sock_recv_done() not called");
    ah_unit_assert(unit, !recv_data->did_call_send_done_cb, "`recv` s_on_sock_send_done() was called");

    struct s_udp_sock_user_data* send_data = &send_sock_user_data;
    ah_unit_assert(unit, send_data->did_call_open_cb, "`send` s_on_sock_open() not called");
    ah_unit_assert(unit, send_data->did_call_close_cb, "`send` s_on_sock_close() not called");
    ah_unit_assert(unit, !send_data->did_call_recv_alloc_cb, "`send` s_on_sock_send_alloc() was called");
    ah_unit_assert(unit, !send_data->did_call_recv_done_cb, "`send` s_on_sock_send_done() was called");
    ah_unit_assert(unit, send_data->did_call_send_done_cb, "`send` s_on_sock_send_done() not called");

    ah_unit_assert(unit, ah_loop_is_term(&loop), "`loop` never terminated");
}

#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(ah_unit_t* unit)
{
# define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)            \
  ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2)); \
  ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv4_t, group_addr, struct ip_mreq, imr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv4_t, interface_addr, struct ip_mreq, imr_interface);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv6_t, group_addr, struct ipv6_mreq, ipv6mr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv6_t, zone_id, struct ipv6_mreq, ipv6mr_interface);

    ah_unit_assert(unit, sizeof(ah_udp_group_ipv4_t) >= sizeof(struct ip_mreq),
        "ah_udp_group_ipv4_t seems to be missing fields");

    ah_unit_assert(unit, sizeof(ah_udp_group_ipv6_t) >= sizeof(struct ipv6_mreq),
        "ah_udp_group_ipv4_t seems to be missing fields");

# undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
