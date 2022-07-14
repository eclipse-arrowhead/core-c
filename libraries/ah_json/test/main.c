// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include <ah/lib.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

void test_json_parse(ah_unit_t* unit);
void test_json_str_compare(ah_unit_t* unit);
void test_json_str_unescape(ah_unit_t* unit);

int main(void)
{
    (void) printf(
        "Arrowhead JSON C Library Unit Tests\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit unit = { 0 };

    test_json_parse(&unit);
    test_json_str_compare(&unit);
    test_json_str_unescape(&unit);

    ah_unit_print_results(&unit);

    return unit.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
