// SPDX-License-Identifier: EPL-2.0

#include <ah/lib.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_json_parse(ah_unit_res_t* res);
void test_json_str_compare(ah_unit_res_t* res);
void test_json_str_escape(ah_unit_res_t* res);
void test_json_str_unescape(ah_unit_res_t* res);

int main(void)
{
    (void) printf(
        "Arrowhead JSON C Library Unit Tests\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit_res res = { 0 };

    test_json_parse(&res);

    test_json_str_compare(&res);
    test_json_str_escape(&res);
    test_json_str_unescape(&res);

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
