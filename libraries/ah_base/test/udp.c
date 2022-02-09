// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/err.h"
#include "ah/sock.h"
#include "ah/unit.h"

#if AH_USE_BSD_SOCKETS
static void s_should_use_same_data_layout_as_platform_mreq(struct ah_unit* unit);
#endif

void test_udp(struct ah_unit* unit)
{
#if AH_USE_BSD_SOCKETS
    s_should_use_same_data_layout_as_platform_mreq(unit);
#endif
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
