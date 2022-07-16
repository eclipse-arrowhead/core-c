// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"
#include "ah/unit.h"

#if AH_IS_WIN32
# include <winsock2.h>
#elif AH_HAS_POSIX
# include <sys/uio.h>
#endif

static void s_should_use_same_data_layout_as_platform_variant(ah_unit_t* unit);

void test_buf(ah_unit_t* unit)
{
    s_should_use_same_data_layout_as_platform_variant(unit);
}

static void s_should_use_same_data_layout_as_platform_variant(ah_unit_t* unit)
{
#define S_ASSERT_FIELD_OFFSET_SIZE_EQ(UNIT, TYPE1, FIELD1, TYPE2, FIELD2)            \
 ah_unit_assert_unsigned_eq(UNIT, offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2)); \
 ah_unit_assert_unsigned_eq(UNIT, sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

#if AH_IS_WIN32

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_buf_t, size, WSABUF, len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_buf_t, base, WSABUF, buf);

    ah_unit_assert(unit, sizeof(ah_buf_t) >= sizeof(WSABUF), "ah_buf_t seems to be missing fields");

#elif AH_HAS_POSIX

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_buf_t, base, struct iovec, iov_base);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(unit, ah_buf_t, size, struct iovec, iov_len);

    ah_unit_assert(unit, sizeof(ah_buf_t) >= sizeof(struct iovec), "ah_buf_t seems to be missing fields");

#endif

#undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
