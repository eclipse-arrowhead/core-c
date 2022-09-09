// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include "ah_i_mbedtls_lib_version.h"

ah_extern const char* ah_mbedtls_lib_version_str(void)
{
    return AH_I_MBEDTLS_LIB_VERSION_STR;
}

ah_extern unsigned short ah_mbedtls_lib_version_major(void)
{
    return AH_I_MBEDTLS_LIB_VERSION_MAJOR;
}

ah_extern unsigned short ah_mbedtls_lib_version_minor(void)
{
    return AH_I_MBEDTLS_LIB_VERSION_MINOR;
}

ah_extern unsigned short ah_mbedtls_lib_version_patch(void)
{
    return AH_I_MBEDTLS_LIB_VERSION_PATCH;
}
