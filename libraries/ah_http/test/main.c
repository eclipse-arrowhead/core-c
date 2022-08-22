// SPDX-License-Identifier: EPL-2.0

#include <ah/lib.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_http(ah_unit_t* unit);
void test_http_parser(ah_unit_t* unit);

int main(void)
{
    (void) printf(
        "Arrowhead HTTP C Library Unit Tests\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit unit = { 0 };

    test_http(&unit);
    test_http_parser(&unit);

    ah_unit_print_results(&unit);

    return unit.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
