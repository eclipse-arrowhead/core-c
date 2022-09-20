// SPDX-License-Identifier: EPL-2.0

/**
 * @example{lineno} ah_json/examples/construct_object.c
 *
 * @see ah_json/include/ah/json.h
 */

// An example of how to construct a JSON representation using C99 standard
// library functions and our ah_json_str_escape() function.

#include <ah/err.h>
#include <ah/json.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    ah_err_t err;
    char err_buf[128u];
    const char* err_ctx;

    const char* sensor_id = "aa-xx-142b";
    float kelvin = 296.55f;

    // Here, we assume that `sensor_id` may contain characters that must be
    // escaped before they can be part of a JSON message. If we had known that
    // `sensor_id` will never contain control characters, backslashes or double
    // quotes, we could have skipped escaping it.

    char sensor_id_buf[32u];
    size_t sensor_id_buf_length = sizeof(sensor_id_buf);
    err = ah_json_str_escape(sensor_id, strlen(sensor_id), sensor_id_buf, &sensor_id_buf_length);
    if (err != AH_ENONE) {
        err_ctx = "ah_json_str_escape()";
        goto handle_err;
    }
    if (sensor_id_buf_length > INT_MAX) {
        err = AH_EDOM;
        err_ctx = "ah_json_str_escape()";
        goto handle_err;
    }

    // We are not ready to produce the actual JSON object.

    char out_buf[128u];
    int size = snprintf(out_buf, sizeof(out_buf), "{\"sensor-id\":\"%.*s\",\"kelvin\":%f}",
        (int) sensor_id_buf_length, sensor_id_buf, kelvin);

    if (size < 0) {
        perror(NULL);
        exit(EXIT_FAILURE);
    }

    if (((size_t) size) > sizeof(out_buf)) {
        fputs("out_buf overflowed\n", stderr);
        exit(EXIT_FAILURE);
    }

    // `out_buf` now contains a JSON object of size `res`. You may, for example,
    // choose to send the contents of `out_buf` over the Internet or some other
    // network. We print it just to make it visible if you run this program.

    printf("%.*s\n", size, out_buf); // Prints `{"sensor_name":"aa-xx-142b","kelvin":296.55}`.

    exit(EXIT_SUCCESS);

handle_err:
    ah_strerror_r(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "%s failed: %s\n", err_ctx, err_buf);
    exit(EXIT_FAILURE);
}
