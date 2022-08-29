// SPDX-License-Identifier: EPL-2.0

/**
 * @example ah_json/examples/construct_object.c
 *
 * An example of how to construct a JSON representation using only C99 standard
 * library functions.
 *
 * @see ah_json/include/ah/json.h
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    const char* sensor_id = "aa-xx-142b";
    float kelvin = 296.55f;

    char buffer[128u];
    int size = snprintf(buffer, sizeof(buffer), "{\"sensor-id\":\"%s\",\"kelvin\":%f}",
        sensor_id, kelvin);

    if (size < 0) {
        perror(NULL);
        exit(EXIT_FAILURE);
    }

    if (((size_t) size) > sizeof(buffer)) {
        fputs("buffer overflowed\n", stderr);
        exit(EXIT_FAILURE);
    }

    // `buffer` now contains a JSON object of size `res`. You may, for example,
    // choose to send the contents of `buffer` over the Internet or some other
    // network.

    printf("%.*s\n", size, buffer); // Prints `{"sensor_name":"aa-xx-142b","kelvin":296.55}`.

    exit(EXIT_SUCCESS);
}
