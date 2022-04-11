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

struct s_recv_sock_data {
    struct ah_buf* buf;
    struct ah_unit* unit;
};

static void s_should_send_and_receive_data(struct ah_unit* unit);
#if AH_USE_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(struct ah_unit* unit);
#endif

void test_udp(struct ah_unit* unit)
{
    s_should_send_and_receive_data(unit);
#if AH_USE_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_mreq(unit);
#endif
}

static void s_on_alloc(struct ah_udp_sock* sock, struct ah_bufvec* bufvec, size_t size)
{
    struct s_recv_sock_data* recv_sock_data = ah_udp_get_user_data(sock);
    if (recv_sock_data == NULL) {
        return;
    }

    struct ah_unit* unit = recv_sock_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert(unit, bufvec != NULL, "bufvec == NULL")) {
        return;
    }

    if (bufvec->items == NULL) {
        if (!ah_unit_assert(unit, recv_sock_data->buf != NULL, "recv_sock_data->buf == NULL")) {
            return;
        }

        bufvec->items = recv_sock_data->buf;
        bufvec->length = 1u;

        recv_sock_data->buf = NULL;
    }
    else {
        if (!ah_unit_assert_unsigned_eq(unit, 1u, bufvec->length)) {
            return;
        }

        recv_sock_data->buf = bufvec->items;

        bufvec->items = 0u;
        bufvec->length = 0u;
    }

    (void) size;
}

static void s_on_recv(struct ah_udp_sock* sock, union ah_sockaddr* remote_addr, struct ah_bufvec* bufvec, size_t size,
    ah_err_t err)
{
    (void) sock;
    (void) remote_addr;
    (void) bufvec;
    (void) size;
    (void) err;
}

static void s_should_send_and_receive_data(struct ah_unit* unit)
{
    ah_err_t err;

    struct ah_loop recv_loop;
    err = ah_loop_init(&recv_loop, &(struct ah_loop_opts) { .capacity = 4 });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    struct ah_udp_sock recv_sock;
    err = ah_udp_init(&recv_sock, &recv_loop, NULL);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    uint8_t recv_buf_octets[16] = { 0 };

    struct s_recv_sock_data recv_sock_data = {
        .buf = &(struct ah_buf) {.octets = recv_buf_octets, .size = sizeof(recv_buf_octets)},
        .unit = unit,
    };
    ah_udp_set_user_data(&recv_sock, &recv_sock_data);

    union ah_sockaddr recv_addr = (union ah_sockaddr) {
        .as_ipv4 = {.family = AH_SOCKFAMILY_IPV4, .port = 0u, .ipaddr = ah_ipaddr_v4_loopback}
    };
    err = ah_udp_open(&recv_sock, &recv_addr, NULL);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    err = ah_udp_recv_start(&recv_sock,
        &(struct ah_udp_recv_ctx) {
            .alloc_cb = s_on_alloc,
            .recv_cb = s_on_recv,
        });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    struct ah_loop send_loop;
    err = ah_loop_init(&send_loop, &(struct ah_loop_opts) { .capacity = 4 });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    struct ah_udp_sock send_sock;
    err = ah_udp_init(&send_sock, &send_loop, NULL);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    union ah_sockaddr send_addr = (union ah_sockaddr) {
        .as_ipv4 = {.family = AH_SOCKFAMILY_IPV4, .port = 0u, .ipaddr = ah_ipaddr_v4_loopback}
    };
    err = ah_udp_open(&send_sock, &send_addr, NULL);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }
}

#if AH_USE_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(struct ah_unit* unit)
{
#    define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)                                          \
        ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2));                            \
        ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, struct ah_udp_group_ipv4, group_addr, struct ip_mreq, imr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, struct ah_udp_group_ipv4, interface_addr, struct ip_mreq, imr_interface);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, struct ah_udp_group_ipv6, group_addr, struct ipv6_mreq, ipv6mr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, struct ah_udp_group_ipv6, zone_id, struct ipv6_mreq, ipv6mr_interface);

    ah_unit_assert(unit, sizeof(struct ah_udp_group_ipv4) >= sizeof(struct ip_mreq),
        "struct ah_udp_group_ipv4 seems to be missing fields");

    ah_unit_assert(unit, sizeof(struct ah_udp_group_ipv6) >= sizeof(struct ipv6_mreq),
        "struct ah_udp_group_ipv4 seems to be missing fields");

#    undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
