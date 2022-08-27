// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include <ah/unit.h>

#if AH_IS_WIN32
# include <winsock2.h>
#elif AH_HAS_POSIX
# include <sys/uio.h>
#endif

static void s_should_use_same_data_layout_as_platform_variant(ah_unit_res_t* res);

void test_buf(ah_unit_res_t* res)
{
    s_should_use_same_data_layout_as_platform_variant(res);
}

static void s_should_use_same_data_layout_as_platform_variant(ah_unit_res_t* res)
{
#define S_ASSERT_FIELD_OFFSET_SIZE_EQ(CTX, RES, TYPE1, FIELD1, TYPE2, FIELD2)               \
 ah_unit_assert_eq_uintmax((CTX), (RES), offsetof(TYPE1, FIELD1), offsetof(TYPE2, FIELD2)); \
 ah_unit_assert_eq_uintmax((CTX), (RES), sizeof((TYPE1) { 0 }.FIELD1), sizeof((TYPE2) { 0 }.FIELD2))

#if AH_IS_WIN32

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_buf_t, size, WSABUF, len);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_buf_t, base, WSABUF, buf);

    ah_unit_assert(res, sizeof(ah_buf_t) >= sizeof(WSABUF), "ah_buf_t seems to be missing fields");

#elif AH_HAS_POSIX

    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_buf_t, base, struct iovec, iov_base);
    S_ASSERT_FIELD_OFFSET_SIZE_EQ(AH_UNIT_CTX, res, ah_buf_t, size, struct iovec, iov_len);

    ah_unit_assert(AH_UNIT_CTX, res, sizeof(ah_buf_t) >= sizeof(struct iovec), "ah_buf_t seems to be missing fields");

#endif

#undef S_ASSERT_FIELD_OFFSET_SIZE_EQ
}
