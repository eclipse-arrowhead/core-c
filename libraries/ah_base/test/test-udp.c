// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/err.h"
#include "ah/ip.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/unit.h"

#if AH_IS_WIN32
#    include <ws2ipdef.h>
#endif

struct s_udp_user_data {
    ah_buf_t* free_buf;

    bool _did_alloc;
    bool _did_receive;
    bool _did_send;

    ah_unit_t* unit;
};

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

static void s_on_alloc(ah_udp_sock_t* sock, ah_bufs_t* bufs, size_t size)
{
    (void) size;

    struct s_udp_user_data* user_data = ah_udp_sock_get_user_data(sock);
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
    if (!ah_unit_assert(unit, user_data->free_buf != NULL, "data->buf == NULL")) {
        return;
    }

    bufs->items = user_data->free_buf;
    bufs->length = 1u;

    user_data->free_buf = NULL;
    user_data->_did_alloc = true;
}

static void s_on_recv(ah_udp_sock_t* sock, ah_sockaddr_t* raddr, ah_bufs_t* bufs, size_t size, ah_err_t err)
{
    struct s_udp_user_data* user_data = ah_udp_sock_get_user_data(sock);
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

    if (!ah_unit_assert(unit, raddr != NULL, "raddr == NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, bufs != NULL, "bufs == NULL")) {
        return;
    }

    if (!ah_unit_assert_unsigned_eq(unit, 18, size)) {
        return;
    }
    if (!ah_unit_assert_unsigned_eq(unit, 1, bufs->length)) {
        return;
    }
    if (!ah_unit_assert(unit, bufs->items != NULL, "bufs->items == NULL")) {
        return;
    }
    if (!ah_unit_assert_cstr_eq(unit, "Hello, Arrowhead!", (char*) bufs->items[0]._octets)) {
        return;
    }

    // Free bufs.
    user_data->free_buf = bufs->items;
    bufs->items = NULL;
    bufs->length = 0u;

    user_data->_did_receive = true;
}

static void s_on_send(ah_udp_sock_t* sock, ah_err_t err)
{
    struct s_udp_user_data* user_data = ah_udp_sock_get_user_data(sock);
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

    user_data->_did_send = true;
}

static void s_should_send_and_receive_data(ah_unit_t* unit)
{
    ah_err_t err;

    // Setup user data.

    uint8_t recv_buf_octets[24] = { 0u };

    struct s_udp_user_data user_data = {
        .free_buf = &(ah_buf_t) {
            ._octets = recv_buf_octets,
            ._size = sizeof(recv_buf_octets),
        },
        .unit = unit,
    };

    // Setup receiver.

    ah_loop_t recv_loop;
    ah_udp_sock_t recv_sock;
    ah_sockaddr_t recv_addr;

    err = ah_loop_init(&recv_loop, &(ah_loop_opts_t) { .capacity = 4 });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_sockaddr_init_ipv4(&recv_addr, 0u, &ah_ipaddr_v4_loopback);

    ah_udp_init(&recv_sock, &recv_loop);
    err = ah_udp_sock_open(&recv_sock, &recv_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    ah_udp_sock_set_user_data(&recv_sock, &user_data);

    err = ah_udp_sock_get_laddr(&recv_sock, &recv_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Receive data.

    err = ah_udp_sock_recv_start(&recv_sock);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Setup sender.

    ah_loop_t send_loop;
    ah_udp_sock_t send_sock;
    ah_sockaddr_t send_addr;

    err = ah_loop_init(&send_loop, &(ah_loop_opts_t) { .capacity = 4 });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    ah_sockaddr_init_ipv4(&send_addr, 0u, &ah_ipaddr_v4_loopback);

    ah_udp_init(&send_sock, &send_loop);
    err = ah_udp_sock_open(&send_sock, &send_addr);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    ah_udp_sock_set_user_data(&send_sock, &user_data);

    // Send data.

    err = ah_udp_sock_send(&send_sock,
        &(ah_udp_send_ctx_t) {
            .raddr = recv_addr,
            .bufs = (ah_bufs_t) {
                .items = &(ah_buf_t) {
                    ._octets = (uint8_t*) "Hello, Arrowhead!",
                    ._size = 18u,
                },
                .length = 1u,
            },
            .send_cb = s_on_send,
        },NULL);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Submit.

    err = ah_loop_run_until(&send_loop, &(struct ah_time) { 0 });
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    struct ah_time deadline;
    err = ah_time_add(ah_time_now(), 10 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }
    err = ah_loop_run_until(&recv_loop, &deadline);
    if (!ah_unit_assert_err_eq(unit, AH_ENONE, err)) {
        return;
    }

    // Check results.

    ah_unit_assert(unit, user_data._did_alloc, "receiver did not allocate memory for message");
    ah_unit_assert(unit, user_data._did_receive, "receiver did not receive sent message");
    ah_unit_assert(unit, user_data._did_send, "sender send callback never invoked");

    // Release all resources.

    err = ah_udp_sock_close(&recv_sock);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);

    err = ah_loop_term(&recv_loop);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);

    err = ah_udp_sock_close(&send_sock);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);

    err = ah_loop_term(&send_loop);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);
}

#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(ah_unit_t* unit)
{
#    define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)                                          \
        ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2));                            \
        ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv4_t, group_addr, struct ip_mreq, imr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv4_t, interface_addr, struct ip_mreq, imr_interface);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv6_t, group_addr, struct ipv6_mreq, ipv6mr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_udp_group_ipv6_t, zone_id, struct ipv6_mreq, ipv6mr_interface);

    ah_unit_assert(unit, sizeof(ah_udp_group_ipv4_t) >= sizeof(struct ip_mreq),
        "ah_udp_group_ipv4_t seems to be missing fields");

    ah_unit_assert(unit, sizeof(ah_udp_group_ipv6_t) >= sizeof(struct ipv6_mreq),
        "ah_udp_group_ipv4_t seems to be missing fields");

#    undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
