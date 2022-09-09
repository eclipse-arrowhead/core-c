// SPDX-License-Identifier: EPL-2.0

#include "ah/mbedtls.h"

#include <ah/meta.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_mbedtls(ah_unit_res_t* res);

int main(void)
{
    (void) printf(
        "Arrowhead MbedTLS C Library Unit Tests\n"
        "- Version:       %s\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_mbedtls_lib_version_str(), ah_meta_commit_str(), ah_meta_platform_str());

    struct ah_unit_res res = { 0 };

    test_mbedtls(&res);

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
