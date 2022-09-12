// SPDX-License-Identifier: EPL-2.0

#include "ah-c/service-discovery.h"

#include <ah/base.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    (void) puts(
        "Arrowhead Service Discovery HTTP/JSON Consumer C Library Unit Tests\n"
        "- Version:       " AH_C_SERVICE_DISCOVERY_VERSION_STR "\n"
        "- Source Commit: " AH_BASE_COMMIT_STR "\n"
        "- Platform:      " AH_BASE_PLATFORM_STR "\n");

    struct ah_unit_res res = { 0 };

    // TODO: Add test suites.

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
