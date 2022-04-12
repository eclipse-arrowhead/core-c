// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/sock.h"

#include "ah/unit.h"

#if AH_USE_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_sockaddr(ah_unit_t* unit);
#endif

void test_sock(ah_unit_t* unit)
{
#if AH_USE_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_sockaddr(unit);
#endif
}

#if AH_USE_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_sockaddr(ah_unit_t* unit)
{
#    define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)                                          \
        ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2));                            \
        ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

#    if AH_I_SOCKADDR_HAS_SIZE
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_any_t, size, struct sockaddr, sa_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, size, struct sockaddr_in, sin_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ip_t, size, struct sockaddr_in6, sin6_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv4_t, size, struct sockaddr_in, sin_len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_sockaddr_ipv6_t, size, struct sockaddr_in6, sin6_len);
#    endif

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

#    undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
