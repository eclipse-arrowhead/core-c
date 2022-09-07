// SPDX-License-Identifier: EPL-2.0

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"
#include "ah/sock.h"
#include "ah/udp.h"

#include <ah/unit.h>

#if AH_IS_WIN32
# include <ws2ipdef.h>
#endif

struct s_sock_obs_ctx {
    ah_udp_sock_t* open_this_sock_on_open;
    ah_udp_out_t* send_this_on_sock_open;

    ah_sockaddr_t laddr;

    size_t* open_socket_count;

    size_t on_open_count;
    size_t on_recv_count;
    size_t on_send_count;
    size_t on_close_count;
    size_t received_message_count;

    ah_unit_res_t* res;
};

static void s_should_send_and_receive_data(ah_unit_res_t* res);
#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(ah_unit_res_t* res);
#endif

void test_udp(ah_unit_res_t* res)
{
    s_should_send_and_receive_data(res);
#if AH_HAS_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_mreq(res);
#endif
}

static void s_on_open(void* ctx_, ah_udp_sock_t* sock, ah_err_t err);
static void s_on_close(void* ctx_, ah_udp_sock_t* sock, ah_err_t err);
static void s_on_recv(void* ctx_, ah_udp_sock_t* sock, ah_udp_in_t* in, ah_err_t err);
static void s_on_send(void* ctx_, ah_udp_sock_t* sock, ah_udp_out_t* out, ah_err_t err);

static const ah_udp_sock_cbs_t s_sock_cbs = {
    .on_open = s_on_open,
    .on_close = s_on_close,
    .on_recv = s_on_recv,
    .on_send = s_on_send,
};

static void s_on_open(void* ctx_, ah_udp_sock_t* sock, ah_err_t err)
{
    struct s_sock_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_open_count += 1u;

    ah_unit_res_t* res = ctx->res;

    ah_udp_sock_t* opened_sock = NULL;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        if (sock != NULL) {
            err = ah_udp_sock_term(sock);
            (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
        }
        return;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, sock != NULL, "sock != NULL")) {
        goto handle_failure;
    }

    (*ctx->open_socket_count) += 1u;

    err = ah_udp_sock_set_reuseaddr(sock, false);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    if (ctx->open_this_sock_on_open != NULL) {
        err = ah_udp_sock_get_laddr(sock, &ctx->laddr);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }

        err = ah_udp_sock_open(ctx->open_this_sock_on_open, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }
        opened_sock = ctx->open_this_sock_on_open;
    }

    if (ctx->send_this_on_sock_open != NULL) {
        err = ah_udp_sock_send(sock, ctx->send_this_on_sock_open);
        if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
            goto handle_failure;
        }
    }

    err = ah_udp_sock_recv_start(sock);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }

    return;

handle_failure:
    if (sock != NULL) {
        err = ah_udp_sock_close(sock);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
    if (opened_sock != NULL) {
        err = ah_udp_sock_close(opened_sock);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_on_recv(void* ctx_, ah_udp_sock_t* sock, ah_udp_in_t* in, ah_err_t err)
{
    struct s_sock_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_recv_count += 1u;

    ah_unit_res_t* res = ctx->res;

    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, in != NULL, "in != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert(AH_UNIT_CTX, res, sock != NULL, "sock != NULL")) {
        goto handle_failure;
    }
    if (!ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, in->nrecv, 18u)) {
        goto handle_failure;
    }
    if (!ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, (char*) in->buf.base, "Hello, Arrowhead!")) {
        goto handle_failure;
    }

    ctx->received_message_count += 1u;

handle_failure:
    if (sock != NULL) {
        err = ah_udp_sock_close(sock);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_on_send(void* ctx_, ah_udp_sock_t* sock, ah_udp_out_t* out, ah_err_t err)
{
    struct s_sock_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_send_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    (void) ah_unit_assert(AH_UNIT_CTX, res, out != NULL, "out != NULL");
    (void) ah_unit_assert(AH_UNIT_CTX, res, sock != NULL, "sock != NULL");

    if (ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, out->nsent, 18u)) {
        (void) ah_unit_assert_eq_cstr(AH_UNIT_CTX, res, (char*) out->buf.base, "Hello, Arrowhead!");
    }

    (void) ah_unit_assert(AH_UNIT_CTX, res, out->raddr != NULL, "out->raddr != NULL");

    if (sock != NULL) {
        err = ah_udp_sock_close(sock);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_on_close(void* ctx_, ah_udp_sock_t* sock, ah_err_t err)
{
    struct s_sock_obs_ctx* ctx = ctx_;
    ah_assert_always(ctx != NULL);
    ctx->on_close_count += 1u;

    ah_unit_res_t* res = ctx->res;

    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    if (!ah_unit_assert(AH_UNIT_CTX, res, sock != NULL, "sock != NULL")) {
        return;
    }

    ah_loop_t* loop = ah_udp_sock_get_loop(sock);
    (void) ah_unit_assert(AH_UNIT_CTX, res, loop != NULL, "loop != NULL");

    err = ah_udp_sock_term(sock);
    (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);

    (*ctx->open_socket_count) -= 1u;

    if (*ctx->open_socket_count == 0u) {
        err = ah_loop_term(loop);
        (void) ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    }
}

static void s_should_send_and_receive_data(ah_unit_res_t* res)
{
    ah_err_t err;

    // Setup event loop.
    ah_loop_t loop;
    err = ah_loop_init(&loop, 4u);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // When this number reaches zero, we terminate the event loop.
    size_t open_socket_count = 0u;

    // Setup receiver socket.
    struct s_sock_obs_ctx recv_sock_obs_ctx = {
        .open_socket_count = &open_socket_count,
        .res = res,
    };
    ah_udp_sock_t recv_sock;
    err = ah_udp_sock_init(&recv_sock, &loop, ah_udp_trans_get_default(), (ah_udp_sock_obs_t) { &s_sock_cbs, &recv_sock_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Setup sender socket.
    ah_udp_out_t send_out = {
        .buf = ah_buf_from((uint8_t*) "Hello, Arrowhead!", 18u),
        .raddr = &recv_sock_obs_ctx.laddr,
    };
    struct s_sock_obs_ctx send_sock_obs_ctx = {
        .send_this_on_sock_open = &send_out,
        .open_socket_count = &open_socket_count,
        .res = res,
    };
    ah_udp_sock_t send_sock;
    err = ah_udp_sock_init(&send_sock, &loop, ah_udp_trans_get_default(), (ah_udp_sock_obs_t) { &s_sock_cbs, &send_sock_obs_ctx });
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // The receiver socket keeps a reference to `send_sock` for us to be able to
    // open it after `recv_sock` is ready to accept incoming datagrams.
    recv_sock_obs_ctx.open_this_sock_on_open = &send_sock;

    // Open receiver socket.
    err = ah_udp_sock_open(&recv_sock, (const ah_sockaddr_t*) &ah_sockaddr_ipv4_loopback);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Execute event loop.
    ah_time_t deadline;
    err = ah_time_add(ah_time_now(), 1 * AH_TIMEDIFF_MS, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }
    err = ah_loop_run_until(&loop, &deadline);
    if (!ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE)) {
        return;
    }

    // Check results after event loop stops executing.

    struct s_sock_obs_ctx* recv_ctx = &recv_sock_obs_ctx;
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, recv_ctx->on_open_count, 1u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, recv_ctx->on_close_count, 1u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, recv_ctx->on_recv_count, 1u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, recv_ctx->on_send_count, 0u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, recv_ctx->received_message_count, 1u);

    struct s_sock_obs_ctx* send_ctx = &send_sock_obs_ctx;
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, send_ctx->on_open_count, 1u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, send_ctx->on_close_count, 1u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, send_ctx->on_recv_count, 0u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, send_ctx->on_send_count, 1u);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, send_ctx->received_message_count, 0u);

    ah_unit_assert(AH_UNIT_CTX, res, ah_loop_is_term(&loop), "`loop` never terminated");
}

#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(ah_unit_res_t* res)
{
# define S_ASSERT_FIELD_OFFSET_SIZE_EQ(CTX, RES, TYPE1, FIELD1, TYPE2, FIELD2)               \
  ah_unit_assert_eq_uintmax((CTX), (RES), offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2)); \
  ah_unit_assert_eq_uintmax((CTX), (RES), sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_udp_group_ipv4_t, group_addr, struct ip_mreq, imr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_udp_group_ipv4_t, interface_addr, struct ip_mreq, imr_interface);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_udp_group_ipv6_t, group_addr, struct ipv6_mreq, ipv6mr_multiaddr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_udp_group_ipv6_t, zone_id, struct ipv6_mreq, ipv6mr_interface);

    ah_unit_assert(AH_UNIT_CTX, res, sizeof(ah_udp_group_ipv4_t) >= sizeof(struct ip_mreq),
        "ah_udp_group_ipv4_t seems to be missing fields");

    ah_unit_assert(AH_UNIT_CTX, res, sizeof(ah_udp_group_ipv6_t) >= sizeof(struct ipv6_mreq),
        "ah_udp_group_ipv4_t seems to be missing fields");

# undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
