// SPDX-License-Identifier: EPL-2.0

#include "ah/lib.h"
#include "ah/unit.h"

#include <stdio.h>
#include <stdlib.h>

void test_buf(ah_unit_res_t* res);
void test_collections_list(ah_unit_res_t* res);
void test_collections_ring(ah_unit_res_t* res);
void test_ip(ah_unit_res_t* res);
void test_math(ah_unit_res_t* res);
void test_sock(ah_unit_res_t* res);
void test_task(ah_unit_res_t* res);
void test_tcp(ah_unit_res_t* res);
void test_time(ah_unit_res_t* res);
void test_udp(ah_unit_res_t* res);
void test_utf8(ah_unit_res_t* res);

int main(void)
{
    (void) printf(
        "Arrowhead Base C Library Unit Tests\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit_res res = { 0 };

    test_buf(&res);
    test_collections_list(&res);
    test_collections_ring(&res);
    test_ip(&res);
    test_math(&res);
    test_sock(&res);
    test_task(&res);
    test_tcp(&res);
    test_time(&res);
    test_udp(&res);
    test_utf8(&res);

    ah_unit_print_results(&res);

    exit(res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
