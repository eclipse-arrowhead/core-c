// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
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
    ah_udp_sock_t* rsock;
    ah_sockaddr_t laddr;

    ah_udp_out_t* out;

    size_t* close_call_counter;

    bool did_call_open_cb;
    bool did_call_recv_cb;
    bool did_call_send_cb;
    bool did_call_close_cb;

    ah_unit_t* unit;
};

static void s_on_open(ah_udp_sock_t* sock, ah_err_t err);
static void s_on_close(ah_udp_sock_t* sock, ah_err_t err);
static void s_on_recv(ah_udp_sock_t* sock, ah_udp_in_t* in, ah_err_t err);
static void s_on_send(ah_udp_sock_t* sock, ah_udp_out_t* out, ah_err_t err);

static const ah_udp_sock_cbs_t s_sock_cbs = {
    .on_open = s_on_open,
    .on_close = s_on_close,
    .on_recv = s_on_recv,
    .on_send = s_on_send,
};

static void s_on_open(ah_udp_sock_t* sock, ah_err_t err)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);
    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    err = ah_udp_sock_set_reuseaddr(sock, false);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    if (user_data->rsock != NULL) {
        err = ah_udp_sock_get_laddr(sock, &user_data->laddr);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }

        err = ah_udp_sock_open(user_data->rsock, (ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
        if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
            return;
        }
    }

    if (user_data->out != NULL) {
        err = ah_udp_sock_send(sock, user_data->out);
    }
    else {
        err = ah_udp_sock_recv_start(sock);
    }

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
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

static void s_on_recv(ah_udp_sock_t* sock, ah_udp_in_t* in, ah_err_t err)
{
    struct s_udp_sock_user_data* user_data = ah_udp_sock_get_user_data(sock);

    ah_unit_t* unit = user_data->unit;

    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    if (!ah_unit_assert(unit, in != NULL, "raddr == NULL")) {
        return;
    }
    if (!ah_unit_assert_unsigned_eq(unit, 18u, in->nread)) {
        return;
    }
    if (!ah_unit_assert_cstr_eq(unit, "Hello, Arrowhead!", (char*) ah_buf_get_base(&in->buf))) {
        return;
    }

    ah_err_t err0 = ah_udp_sock_close(sock);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err0)) {
        return;
    }

    user_data->did_call_recv_cb = true;
}

static void s_on_send(ah_udp_sock_t* sock, ah_udp_out_t* out, ah_err_t err)
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

    if (!ah_unit_assert(unit, out != NULL, "out == NULL")) {
        return;
    }

    if (!ah_unit_assert_unsigned_eq(unit, 18u, out->nsent)) {
        return;
    }
    if (!ah_unit_assert_cstr_eq(unit, "Hello, Arrowhead!", (char*) ah_buf_get_base(&out->buf))) {
        return;
    }

    if (!ah_unit_assert(unit, out->raddr != NULL, "out->raddr == NULL")) {
        return;
    }

    err = ah_udp_sock_close(sock);
    if (!ah_unit_assert_err_eq(user_data->unit, AH_ENONE, err)) {
        return;
    }

    user_data->did_call_send_cb = true;
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

    // Setup receiver socket.

    struct s_udp_sock_user_data recv_sock_user_data = {
        .close_call_counter = &close_call_counter,
        .unit = unit,
    };

    ah_udp_sock_t recv_sock;
    err = ah_udp_sock_init(&recv_sock, &loop, ah_udp_trans_get_default(), &s_sock_cbs);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_udp_sock_set_user_data(&recv_sock, &recv_sock_user_data);

    // Setup sender socket.

    ah_udp_out_t send_out = {
        .buf = ah_buf_from((uint8_t*) "Hello, Arrowhead!", 18u),
        .raddr = &recv_sock_user_data.laddr,
    };

    struct s_udp_sock_user_data send_sock_user_data = {
        .out = &send_out,
        .close_call_counter = &close_call_counter,
        .unit = unit,
    };

    ah_udp_sock_t send_sock;
    err = ah_udp_sock_init(&send_sock, &loop, ah_udp_trans_get_default(), &s_sock_cbs);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_udp_sock_set_user_data(&send_sock, &send_sock_user_data);

    // Open receiver socket, which will open sender socket, and so on.

    recv_sock_user_data.rsock = &send_sock;
    err = ah_udp_sock_open(&recv_sock, (ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
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
    ah_unit_assert(unit, recv_data->did_call_recv_cb, "`recv` s_on_sock_recv_done() not called");
    ah_unit_assert(unit, !recv_data->did_call_send_cb, "`recv` s_on_sock_send_done() was called");

    struct s_udp_sock_user_data* send_data = &send_sock_user_data;
    ah_unit_assert(unit, send_data->did_call_open_cb, "`send` s_on_sock_open() not called");
    ah_unit_assert(unit, send_data->did_call_close_cb, "`send` s_on_sock_close() not called");
    ah_unit_assert(unit, !send_data->did_call_recv_cb, "`send` s_on_sock_send_done() was called");
    ah_unit_assert(unit, send_data->did_call_send_cb, "`send` s_on_sock_send_done() not called");

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
