// SPDX-License-Identifier: EPL-2.0

#include <ah/lib.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_mbedtls(ah_unit_res_t* res);

int main(void)
{
    (void) printf(
        "Arrowhead MbedTLS C Library Unit Tests\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit_res res = { 0 };

    test_mbedtls(&res);

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
