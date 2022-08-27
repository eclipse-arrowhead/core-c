// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/ip.h"

#include <ah/unit.h>
#include <string.h>

struct s_stringify_ipv4_address_test {
    ah_unit_ctx_t ctx;
    ah_ipaddr_v4_t address;
    const char* expected_result;
};

struct s_stringify_ipv6_address_test {
    ah_unit_ctx_t ctx;
    ah_ipaddr_v6_t address;
    const char* expected_result;
};

static void s_should_stringify_ipv4_addresses(struct ah_unit_res* res);
static void s_should_stringify_ipv6_addresses(struct ah_unit_res* res);
static void s_should_handle_too_small_output_buffer_when_stringifying_ipv4_address(struct ah_unit_res* res);
static void s_should_handle_too_small_output_buffer_when_stringifying_ipv6_address(struct ah_unit_res* res);

void test_ip(struct ah_unit_res* res)
{
    s_should_stringify_ipv4_addresses(res);
    s_should_stringify_ipv6_addresses(res);
    s_should_handle_too_small_output_buffer_when_stringifying_ipv4_address(res);
    s_should_handle_too_small_output_buffer_when_stringifying_ipv6_address(res);
}

void s_assert_stringify_ipv4_address_tests(ah_unit_res_t* res, struct s_stringify_ipv4_address_test* tests)
{
    char buf[AH_IPADDR_V4_STRLEN_MAX];

    for (struct s_stringify_ipv4_address_test* test = &tests[0u]; test->expected_result != NULL; test = &test[1u]) {
        memset(buf, 0, sizeof(buf));
        size_t actual_length = sizeof(buf);

        ah_err_t err = ah_ipaddr_v4_stringify(&test->address, buf, &actual_length);
        if (ah_unit_assert_eq_err(test->ctx, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_str(test->ctx, res, buf, actual_length, test->expected_result, strlen(test->expected_result));
        }
    }
}

static void s_should_stringify_ipv4_addresses(struct ah_unit_res* res)
{
    s_assert_stringify_ipv4_address_tests(res,
        (struct s_stringify_ipv4_address_test[]) {
            { AH_UNIT_CTX, { { 0, 0, 0, 0 } }, "0.0.0.0" },
            { AH_UNIT_CTX, { { 127, 0, 0, 1 } }, "127.0.0.1" },
            { AH_UNIT_CTX, { { 10, 1, 25, 47 } }, "10.1.25.47" },
            { AH_UNIT_CTX, { { 255, 255, 255, 255 } }, "255.255.255.255" },
            { { 0u } },
        });
}

void s_assert_stringify_ipv6_address_tests(ah_unit_res_t* res, struct s_stringify_ipv6_address_test* tests)
{
    char buf[AH_IPADDR_V6_STRLEN_MAX];

    for (struct s_stringify_ipv6_address_test* test = &tests[0u]; test->expected_result != NULL; test = &test[1u]) {
        memset(buf, 0, sizeof(buf));
        size_t actual_length = sizeof(buf);

        ah_err_t err = ah_ipaddr_v6_stringify(&test->address, buf, &actual_length);
        if (ah_unit_assert_eq_err(test->ctx, res, err, AH_ENONE)) {
            (void) ah_unit_assert_eq_str(test->ctx, res, buf, actual_length, test->expected_result, strlen(test->expected_result));
        }
    }
}

static void s_should_stringify_ipv6_addresses(struct ah_unit_res* res)
{
    s_assert_stringify_ipv6_address_tests(res,
        (struct s_stringify_ipv6_address_test[]) {
            { AH_UNIT_CTX, { { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 } }, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210" },
            { AH_UNIT_CTX, { { 0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A } }, "1080::8:800:200C:417A" },
            { AH_UNIT_CTX, { { 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43 } }, "FF01::43" },
            { AH_UNIT_CTX, { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } }, "::1" },
            { AH_UNIT_CTX, { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } }, "::" },
            { AH_UNIT_CTX, { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 13, 1, 68, 3 } }, "::13.1.68.3" },
            { AH_UNIT_CTX, { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 129, 144, 52, 38 } }, "::FFFF:129.144.52.38" },
            { AH_UNIT_CTX, { { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xF7, 0x30, 0x40, 0x50, 0x60 } }, "0:1::FFF7:3040:5060" },
            { { 0u } },
        });
}

static void s_should_handle_too_small_output_buffer_when_stringifying_ipv4_address(struct ah_unit_res* res)
{
    // Should produce "127.0.30.40", which has 11 characters and a null terminator.
    ah_ipaddr_v4_t ipv4_address = {
        .octets = { 127, 0, 30, 45 },
    };

    char buffer[AH_IPADDR_V4_STRLEN_MAX];
    ah_err_t err;
    size_t size;

    size = 0u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_EOVERFLOW);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, 0u, size);

    size = 11u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_EOVERFLOW);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 11u);

    size = 12u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 11u);

    size = 19u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 11u);
}

static void s_should_handle_too_small_output_buffer_when_stringifying_ipv6_address(struct ah_unit_res* res)
{
    // Should produce "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", which has 39 characters and a null terminator.
    ah_ipaddr_v6_t ipv6_address = {
        .octets = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
    };

    char buffer[AH_IPADDR_V6_STRLEN_MAX];
    ah_err_t err;
    size_t size;

    size = 0u;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_EOVERFLOW);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 0u);

    size = 39u;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_EOVERFLOW);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 39u);

    size = 40u;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 39u);

    size = AH_IPADDR_V6_STRLEN_MAX;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_eq_err(AH_UNIT_CTX, res, err, AH_ENONE);
    ah_unit_assert_eq_uintmax(AH_UNIT_CTX, res, size, 39u);
}
