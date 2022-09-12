// SPDX-License-Identifier: EPL-2.0

#include "ah/http.h"

#include <ah/base.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_http(ah_unit_res_t* res);
void test_http_parser(ah_unit_res_t* res);

int main(void)
{
    (void) puts(
        "Arrowhead HTTP C Library Unit Tests\n"
        "- Version:       " AH_HTTP_VERSION_STR "\n"
        "- Source Commit: " AH_BASE_COMMIT_STR "\n"
        "- Platform:      " AH_BASE_PLATFORM_STR "\n");

    struct ah_unit_res res = { 0 };

    test_http(&res);
    test_http_parser(&res);

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
