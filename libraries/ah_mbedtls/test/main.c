// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include <ah/base.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_mbedtls(ah_unit_res_t* res);

int main(void)
{
    (void) puts(
        "Arrowhead MbedTLS C Library Unit Tests\n"
        "- Version:       " AH_MBEDTLS_VERSION_STR "\n"
        "- Source Commit: " AH_BASE_COMMIT_STR "\n"
        "- Platform:      " AH_BASE_PLATFORM_STR "\n");

    struct ah_unit_res res = { 0 };

    test_mbedtls(&res);

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
