// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/meta.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_http(ah_unit_res_t* res);
void test_http_parser(ah_unit_res_t* res);

int main(void)
{
    (void) printf(
        "Arrowhead HTTP C Library Unit Tests\n"
        "- Version:       %s\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n\n",
        ah_http_lib_version_str(), ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit_res res = { 0 };

    test_http(&res);
    test_http_parser(&res);

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
