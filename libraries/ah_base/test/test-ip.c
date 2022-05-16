// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/ip.h"
#include "ah/unit.h"

#include <string.h>

static void s_should_stringify_ipv4_addresses(struct ah_unit* unit);
static void s_should_stringify_ipv6_addresses(struct ah_unit* unit);
static void s_should_handle_too_small_output_buffer_when_stringifying_ipv4_address(struct ah_unit* unit);
static void s_should_handle_too_small_output_buffer_when_stringifying_ipv6_address(struct ah_unit* unit);

void test_ip(struct ah_unit* unit)
{
    s_should_stringify_ipv4_addresses(unit);
    s_should_stringify_ipv6_addresses(unit);
    s_should_handle_too_small_output_buffer_when_stringifying_ipv4_address(unit);
    s_should_handle_too_small_output_buffer_when_stringifying_ipv6_address(unit);
}

static void s_should_stringify_ipv4_addresses(struct ah_unit* unit)
{
#define STRINGIFY_IPV4_ADDRESS_AND_COMPARE(P0, P1, P2, P3, EXPECTED) \
 do {                                                                \
  ah_ipaddr_v4_t _addr = { 0u };                                     \
  memcpy(_addr.octets, (uint8_t[]) { P0, P1, P2, P3 }, 4);           \
                                                                     \
  char _buffer[AH_IPADDR_V4_STRLEN_MAX];                             \
  size_t _size = sizeof(_buffer);                                    \
  ah_err_t _err = ah_ipaddr_v4_stringify(&_addr, _buffer, &_size);   \
  if (ah_unit_assert_err_eq(unit, AH_ENONE, _err)) {                 \
   _buffer[sizeof(_buffer) - 1] = 0;                                 \
   ah_unit_assert_cstr_eq(unit, _buffer, EXPECTED);                  \
  }                                                                  \
 } while (false)

    STRINGIFY_IPV4_ADDRESS_AND_COMPARE(0, 0, 0, 0, "0.0.0.0");
    STRINGIFY_IPV4_ADDRESS_AND_COMPARE(127, 0, 0, 1, "127.0.0.1");
    STRINGIFY_IPV4_ADDRESS_AND_COMPARE(255, 255, 255, 255, "255.255.255.255");

#undef STRINGIFY_IPV4_ADDRESS_AND_COMPARE
}

static void s_should_stringify_ipv6_addresses(struct ah_unit* unit)
{
#define STRINGIFY_IPV6_ADDRESS_AND_COMPARE(P0, P1, P2, P3, P4, P5, P6, P7, P8, P9, PA, PB, PC, PD, PE, PF, EXPECTED) \
 do {                                                                                                                \
  ah_ipaddr_v6_t _addr = { 0u };                                                                                     \
  memcpy(_addr.octets, (uint8_t[]) { P0, P1, P2, P3, P4, P5, P6, P7, P8, P9, PA, PB, PC, PD, PE, PF }, 16);          \
                                                                                                                     \
  char _buffer[AH_IPADDR_V6_STRLEN_MAX];                                                                             \
  size_t _size = sizeof(_buffer);                                                                                    \
  ah_err_t _err = ah_ipaddr_v6_stringify(&_addr, _buffer, &_size);                                                   \
  if (ah_unit_assert_err_eq(unit, AH_ENONE, _err)) {                                                                 \
   _buffer[sizeof(_buffer) - 1] = 0;                                                                                 \
   ah_unit_assert_cstr_eq(unit, _buffer, EXPECTED);                                                                  \
  }                                                                                                                  \
 } while (false)

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A,
        "1080::8:800:200C:417A");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43,
        "FF01::43");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        "::1");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        "::");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 13, 1, 68, 3,
        "::13.1.68.3");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 129, 144, 52, 38,
        "::FFFF:129.144.52.38");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xF7, 0x30, 0x40, 0x50, 0x60,
        "0:1::FFF7:3040:5060");

#undef STRINGIFY_IPV6_ADDRESS_AND_COMPARE
}

static void s_should_handle_too_small_output_buffer_when_stringifying_ipv4_address(struct ah_unit* unit)
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
    ah_unit_assert_err_eq(unit, AH_ENOSPC, err);
    ah_unit_assert_unsigned_eq(unit, size, 0u);

    size = 11u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_err_eq(unit, AH_ENOSPC, err);
    ah_unit_assert_unsigned_eq(unit, size, 11u);

    size = 12u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);
    ah_unit_assert_unsigned_eq(unit, size, 11u);

    size = 19u;
    err = ah_ipaddr_v4_stringify(&ipv4_address, buffer, &size);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);
    ah_unit_assert_unsigned_eq(unit, size, 11u);
}

static void s_should_handle_too_small_output_buffer_when_stringifying_ipv6_address(struct ah_unit* unit)
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
    ah_unit_assert_err_eq(unit, AH_ENOSPC, err);
    ah_unit_assert_unsigned_eq(unit, size, 0u);

    size = 39u;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_err_eq(unit, AH_ENOSPC, err);
    ah_unit_assert_unsigned_eq(unit, size, 39u);

    size = 40u;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);
    ah_unit_assert_unsigned_eq(unit, size, 39u);

    size = AH_IPADDR_V6_STRLEN_MAX;
    err = ah_ipaddr_v6_stringify(&ipv6_address, buffer, &size);
    ah_unit_assert_err_eq(unit, AH_ENONE, err);
    ah_unit_assert_unsigned_eq(unit, size, 39u);
}
