// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/unit.h"

#if AH_USE_IOVEC
#    include <sys/uio.h>
#endif

#if AH_USE_IOVEC
static void s_should_use_same_data_layout_as_platform_iovec(struct ah_unit* unit);
#endif

void test_buf(struct ah_unit* unit)
{
#if AH_USE_IOVEC
    s_should_use_same_data_layout_as_platform_iovec(unit);
#endif
}

#if AH_USE_IOVEC
static void s_should_use_same_data_layout_as_platform_iovec(struct ah_unit* unit)
{
#    define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)                                          \
        ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2));                            \
        ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, struct ah_buf, octets, struct iovec, iov_base);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, struct ah_buf, size, struct iovec, iov_len);

    ah_unit_assert(unit, sizeof(struct ah_buf) >= sizeof(struct iovec),
        "struct ah_buf seems to be missing fields");

#    undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
#endif
