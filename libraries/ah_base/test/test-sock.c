// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/sock.h"
#include "ah/unit.h"

#if AH_HAS_BSD_SOCKETS && AH_IS_WIN32
# include <ws2ipdef.h>
#endif

static void s_should_stringify_ipv4_sockaddrs(ah_unit_t* unit);
static void s_should_stringify_ipv6_sockaddrs(ah_unit_t* unit);
#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_sockaddr(ah_unit_t* unit);
#endif

void test_sock(ah_unit_t* unit)
{
    s_should_stringify_ipv4_sockaddrs(unit);
    s_should_stringify_ipv6_sockaddrs(unit);
#if AH_HAS_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_sockaddr(unit);
#endif
}

static void s_should_stringify_ipv4_sockaddrs(ah_unit_t* unit)
{
#define STRINGIFY_IPV4_ADDRESS_AND_COMPARE(P0, P1, P2, P3, PORT, EXPECTED)               \
 do {                                                                                    \
  ah_sockaddr_t _addr = { .as_ipv4 = { .family = AH_SOCKFAMILY_IPV4, .port = (PORT) } }; \
  memcpy(_addr.as_ipv4.ipaddr.octets, (uint8_t[]) { P0, P1, P2, P3 }, 4);                \
                                                                                         \
  char _buffer[AH_SOCKADDR_IPV4_STRLEN_MAX];                                             \
  size_t _size = sizeof(_buffer);                                                        \
  ah_err_t _err = ah_sockaddr_stringify(&_addr, _buffer, &_size);                        \
  if (ah_unit_assert_err_eq(unit, AH_ENONE, _err)) {                                     \
   _buffer[sizeof(_buffer) - 1] = 0;                                                     \
   ah_unit_assert_cstr_eq(unit, _buffer, EXPECTED);                                      \
  }                                                                                      \
 } while (false)

    STRINGIFY_IPV4_ADDRESS_AND_COMPARE(0, 0, 0, 0, 0, "0.0.0.0:0");
    STRINGIFY_IPV4_ADDRESS_AND_COMPARE(127, 0, 0, 1, 80, "127.0.0.1:80");
    STRINGIFY_IPV4_ADDRESS_AND_COMPARE(255, 255, 255, 255, 65535, "255.255.255.255:65535");

#undef STRINGIFY_IPV4_ADDRESS_AND_COMPARE
}

static void s_should_stringify_ipv6_sockaddrs(ah_unit_t* unit)
{
#define STRINGIFY_IPV6_ADDRESS_AND_COMPARE(P0, P1, P2, P3, P4, P5, P6, P7, P8, P9, PA, PB, PC, PD, PE, PF, ZONE_ID, PORT, EXPECTED) \
 do {                                                                                                                               \
  ah_sockaddr_t _addr = { .as_ipv6 = { .family = AH_SOCKFAMILY_IPV6, .zone_id = (ZONE_ID), .port = (PORT) } };                      \
  memcpy(_addr.as_ipv6.ipaddr.octets, (uint8_t[]) { P0, P1, P2, P3, P4, P5, P6, P7, P8, P9, PA, PB, PC, PD, PE, PF }, 16);          \
                                                                                                                                    \
  char _buffer[AH_SOCKADDR_IPV6_STRLEN_MAX];                                                                                        \
  size_t _size = sizeof(_buffer);                                                                                                   \
  ah_err_t _err = ah_sockaddr_stringify(&_addr, _buffer, &_size);                                                                   \
  if (ah_unit_assert_err_eq(unit, AH_ENONE, _err)) {                                                                                \
   _buffer[sizeof(_buffer) - 1] = 0;                                                                                                \
   ah_unit_assert_cstr_eq(unit, _buffer, EXPECTED);                                                                                 \
  }                                                                                                                                 \
 } while (false)

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0u, 0u,
        "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:0");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A,
        1u, 8080u,
        "[1080::8:800:200C:417A%251]:8080");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43,
        0u, 65535u,
        "[FF01::43]:65535");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        4294967295u, 1u,
        "[::1%254294967295]:1");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0u, 0u,
        "[::]:0");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 13, 1, 68, 3,
        0u, 48444u,
        "[::13.1.68.3]:48444");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 129, 144, 52, 38,
        4u, 8002u,
        "[::FFFF:129.144.52.38%254]:8002");

    STRINGIFY_IPV6_ADDRESS_AND_COMPARE(
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xF7, 0x30, 0x40, 0x50, 0x60,
        3u, 80u,
        "[0:1::FFF7:3040:5060%253]:80");

#undef STRINGIFY_IPV6_ADDRESS_AND_COMPARE
}

#if AH_HAS_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_sockaddr(ah_unit_t* unit)
{
# define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)            \
  ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2)); \
  ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

# if AH_I_SOCKADDR_HAS_SIZE
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_any_t, size, struct sockaddr, sa_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, size, struct sockaddr_in, sin_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, size, struct sockaddr_in6, sin6_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv4_t, size, struct sockaddr_in, sin_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv6_t, size, struct sockaddr_in6, sin6_len);
# endif

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_any_t, family, struct sockaddr, sa_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, family, struct sockaddr_in, sin_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, family, struct sockaddr_in6, sin6_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv4_t, family, struct sockaddr_in, sin_family);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv6_t, family, struct sockaddr_in6, sin6_family);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, port, struct sockaddr_in, sin_port);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, port, struct sockaddr_in6, sin6_port);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv4_t, port, struct sockaddr_in, sin_port);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv6_t, port, struct sockaddr_in6, sin6_port);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv4_t, ipaddr, struct sockaddr_in, sin_addr);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv6_t, ipaddr, struct sockaddr_in6, sin6_addr);

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv6_t, zone_id, struct sockaddr_in6, sin6_scope_id);

# undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
