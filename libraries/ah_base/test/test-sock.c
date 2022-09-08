// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/sock.h"

#include <ah/unit.h>

#if AH_HAS_BSD_SOCKETS && AH_IS_WIN32
# include <ws2ipdef.h>
#endif

struct s_stringify_sockaddr_test {
    ah_unit_ctx_t ctx;
    unsigned sockfamily;
    const uint8_t address[16u];
    uint32_t zone_id;
    uint16_t port;
    const char* expected_result;
};

static void s_should_stringify_sockaddrs(ah_unit_res_t* res);
#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_sockaddr(ah_unit_res_t* res);
#endif

void test_sock(ah_unit_res_t* res)
{
    s_should_stringify_sockaddrs(res);
#if AH_HAS_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_sockaddr(res);
#endif
}

void s_assert_stringify_sockaddr_tests(ah_unit_res_t* res, struct s_stringify_sockaddr_test* tests)
{
    char actual[AH_SOCKADDR_ANY_STRLEN_MAX];

    for (struct s_stringify_sockaddr_test* test = &tests[0u]; test->expected_result != NULL; test = &test[1u]) {
        memset(actual, 0, sizeof(actual));
        size_t actual_length = sizeof(actual);

        ah_sockaddr_t sockaddr;

        ah_err_t err;

        if (test->sockfamily == AH_SOCKFAMILY_IPV4) {
            err = ah_sockaddr_init_ipv4(&sockaddr, test->port, (const ah_ipaddr_v4_t*) test->address);
        }
        else {
            err = ah_sockaddr_init_ipv6(&sockaddr, test->port, (const ah_ipaddr_v6_t*) test->address, test->zone_id);
        }
        if (!ah_unit_assert_eq_err(test->ctx, res, err, AH_ENONE)) {
            continue;
        }

        err = ah_sockaddr_stringify(&sockaddr, actual, &actual_length);
        if (ah_unit_assert_eq_err(test->ctx, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_str(test->ctx, res, actual, actual_length, test->expected_result, strlen(test->expected_result));
        }
    }
}

static void s_should_stringify_sockaddrs(struct ah_unit_res* res)
{
    s_assert_stringify_sockaddr_tests(res,
        (struct s_stringify_sockaddr_test[]) {
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV4, { 0u, 0u, 0u, 0u }, 0u, 0u,
                "0.0.0.0:0" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV4, { 127u, 0u, 0u, 1u }, 0u, 80u,
                "127.0.0.1:80" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV4, { 10u, 1u, 25u, 47u }, 0u, 8080u,
                "10.1.25.47:8080" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV4, { 255u, 255u, 255u, 255u }, 0u, 65535u,
                "255.255.255.255:65535" },

            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 }, 0u, 0u,
                "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:0" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A }, 1u, 8080u,
                "[1080::8:800:200C:417A%251]:8080" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 }, 0u, 65535u,
                "[FF01::43]:65535" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 4294967295u, 1u,
                "[::1%254294967295]:1" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0u, 0u,
                "[::]:0" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 13, 1, 68, 3 }, 0u, 48444u,
                "[::13.1.68.3]:48444" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 129, 144, 52, 38 }, 4u, 8002u,
                "[::FFFF:129.144.52.38%254]:8002" },
            { AH_UNIT_CTX, AH_SOCKFAMILY_IPV6, { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xF7, 0x30, 0x40, 0x50, 0x60 }, 3u, 80u,
                "[0:1::FFF7:3040:5060%253]:80" },

            { { 0u }, 0u, { 0u }, 0u, 0u, NULL },
        });
}

#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_sockaddr(ah_unit_res_t* res)
{
# define S_ASSERT_FIELD_OFFSET_SIZE_EQ(CTX, RES, TYPE1, FIELD1, TYPE2, FIELD2)               \
  ah_unit_assert_eq_uintmax((CTX), (RES), offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2)); \
  ah_unit_assert_eq_uintmax((CTX), (RES), sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

# if AH_I_SOCKADDR_HAS_SIZE
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_any_t, size, struct sockaddr, sa_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ip_t, size, struct sockaddr_in, sin_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ip_t, size, struct sockaddr_in6, sin6_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv4_t, size, struct sockaddr_in, sin_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv6_t, size, struct sockaddr_in6, sin6_len);
# endif

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_any_t, family, struct sockaddr, sa_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ip_t, family, struct sockaddr_in, sin_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ip_t, family, struct sockaddr_in6, sin6_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv4_t, family, struct sockaddr_in, sin_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv6_t, family, struct sockaddr_in6, sin6_family);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ip_t, port, struct sockaddr_in, sin_port);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ip_t, port, struct sockaddr_in6, sin6_port);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv4_t, port, struct sockaddr_in, sin_port);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv6_t, port, struct sockaddr_in6, sin6_port);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv4_t, ipaddr, struct sockaddr_in, sin_addr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv6_t, ipaddr, struct sockaddr_in6, sin6_addr);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv4_t, zero, struct sockaddr_in, sin_zero);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_sockaddr_ipv6_t, zone_id, struct sockaddr_in6, sin6_scope_id);

    ah_unit_assert(AH_UNIT_CTX, res, sizeof(ah_sockaddr_ipv4_t) >= sizeof(struct sockaddr_in),
        "ah_sockaddr_ipv4_t seems to be missing fields");

    ah_unit_assert(AH_UNIT_CTX, res, sizeof(ah_sockaddr_ipv6_t) >= sizeof(struct sockaddr_in6),
        "ah_sockaddr_ipv6_t seems to be missing fields");

# undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
