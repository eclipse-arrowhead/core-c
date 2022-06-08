// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include <ah/lib.h>
#include <ah/unit.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    (void) printf(
        "Arrowhead MbedTLS C Library Unit Tests\n"
        "- Source Commit: %s\n"
        "- Platform:      %s\n",
        ah_lib_commit_str(), ah_lib_platform_str());

    struct ah_unit unit = { 0 };

    ah_unit_print_results(&unit);

    return unit.fail_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
