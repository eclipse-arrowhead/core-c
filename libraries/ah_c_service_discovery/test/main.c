// SPDX-License-Identifier: EPL-2.0

#include "ah-c/service-discovery.h"

#include <ah/meta.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    (void) printf(
        "Arrowhead Service Discovery HTTP/JSON Consumer C Library Unit Tests\n"
        "- Version:       %s\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n\n",
        ah_c_service_discovery_lib_version_str(),
        ah_meta_commit_str(), ah_meta_platform_str());

    struct ah_unit_res res = { 0 };

    // TODO: Add test suites.

    ah_unit_print_results(&res);

    return res.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
