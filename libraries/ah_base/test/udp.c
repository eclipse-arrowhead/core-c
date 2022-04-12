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

struct s_udp_user_data {
    struct ah_buf* free_buf;

    bool _did_alloc;
    bool _did_receive;
    bool _did_send;

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
    (void) size;

    struct s_udp_user_data* user_data = ah_udp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    struct ah_unit* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert(unit, bufvec != NULL, "bufvec == NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, bufvec->items == NULL, "bufvec->items != NULL")) {
        return;
    }
    if (!ah_unit_assert(unit, user_data->free_buf != NULL, "user_data->buf == NULL")) {
        return;
    }

    bufvec->items = user_data->free_buf;
    bufvec->length = 1u;

    user_data->free_buf = NULL;
    user_data->_did_alloc = true;
}

static void s_on_recv(struct ah_udp_sock* sock, union ah_sockaddr* remote_addr, struct ah_bufvec* bufvec, size_t size,
    ah_err_t err)
{
    struct s_udp_user_data* user_data = ah_udp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    struct ah_unit* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    ah_unit_assert(unit, remote_addr != NULL, "remote_addr == NULL");
    ah_unit_assert(unit, bufvec != NULL, "bufvec == NULL");

    if (!ah_unit_assert_unsigned_eq(unit, 18, size)) {
        return;
    }
    if (!ah_unit_assert_unsigned_eq(unit, 1, bufvec->length)) {
        return;
    }
    if (!ah_unit_assert(unit, bufvec->items != NULL, "bufvec->items == NULL")) {
        return;
    }
    if (!ah_unit_assert_str_eq(unit, "Hello, Arrowhead!", (char*) bufvec->items[0].octets)) {
        return;
    }

    // Free bufvec.
    user_data->free_buf = bufvec->items;
    bufvec->items = NULL;
    bufvec->length = 0u;

    user_data->_did_receive = true;
}

static void s_on_send(struct ah_udp_sock* sock, ah_err_t err)
{
    struct s_udp_user_data* user_data = ah_udp_get_user_data(sock);
    if (user_data == NULL) {
        return;
    }

    struct ah_unit* unit = user_data->unit;
    if (unit == NULL) {
        return;
    }

    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    user_data->_did_send = true;
}

static void s_should_send_and_receive_data(struct ah_unit* unit)
{
    ah_err_t err;

    // Setup user data.

    uint8_t recv_buf_octets[24] = { 0u };

    struct s_udp_user_data user_data = {
        .free_buf = &(struct ah_buf) {
            .octets = recv_buf_octets,
            .size = sizeof(recv_buf_octets),
        },
        .unit = unit,
    };

    // Setup receiver.

    struct ah_loop recv_loop;
    struct ah_udp_sock recv_sock;
    union ah_sockaddr recv_addr;

    err = ah_loop_init(&recv_loop, &(struct ah_loop_opts) { .capacity = 4 });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    ah_sockaddr_init_ipv4(&recv_addr, 0u, &ah_ipaddr_v4_loopback);

    err = ah_udp_open(&recv_sock, &recv_loop, &recv_addr, NULL);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }
    ah_udp_set_user_data(&recv_sock, &user_data);

    err = ah_udp_get_local_addr(&recv_sock, &recv_addr);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    // Receive data.

    err = ah_udp_recv_start(&recv_sock,
        &(struct ah_udp_recv_ctx) {
            .alloc_cb = s_on_alloc,
            .recv_cb = s_on_recv,
        });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    // Setup sender.

    struct ah_loop send_loop;
    struct ah_udp_sock send_sock;
    union ah_sockaddr send_addr;

    err = ah_loop_init(&send_loop, &(struct ah_loop_opts) { .capacity = 4 });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    ah_sockaddr_init_ipv4(&send_addr, 0u, &ah_ipaddr_v4_loopback);

    err = ah_udp_open(&send_sock, &send_loop, &send_addr, NULL);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }
    ah_udp_set_user_data(&send_sock, &user_data);

    // Send data.

    err = ah_udp_send(&send_sock,
        &(struct ah_udp_send_ctx) {
            .remote_addr = recv_addr,
            .bufvec = (struct ah_bufvec) {
                .items = &(struct ah_buf) {
                    .octets = (uint8_t*) "Hello, Arrowhead!",
                    .size = 18u,
                },
                .length = 1u,
            },
            .send_cb = s_on_send,
        });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    // Submit.

    err = ah_loop_run_until(&send_loop, &(struct ah_time) { 0 });
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    struct ah_time deadline;
    err = ah_time_add(ah_time_now(), 10 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }
    err = ah_loop_run_until(&recv_loop, &deadline);
    if (!ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror)) {
        return;
    }

    // Check results.

    ah_unit_assert(unit, user_data._did_alloc, "receiver did not allocate memory for message");
    ah_unit_assert(unit, user_data._did_receive, "receiver did not receive sent message");
    ah_unit_assert(unit, user_data._did_send, "sender send callback never invoked");

    // Release all resources.

    err = ah_udp_close(&recv_sock, NULL);
    ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror);

    err = ah_loop_term(&recv_loop);
    ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror);

    err = ah_udp_close(&send_sock, NULL);
    ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror);

    err = ah_loop_term(&send_loop);
    ah_unit_assert_enum_eq(unit, AH_ENONE, err, ah_strerror);
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
