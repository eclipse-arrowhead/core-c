// SPDX-License-Identifier: EPL-2.0

/**
 * @example{lineno} ah_json/examples/interpret_object.c
 *
 * @see ah_json/include/ah/json.h
 */

// An example of how to interpret a JSON representation using our
// ah_json_parse() function and some relevant utility functions.

#include <ah/err.h>
#include <ah/json.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    ah_err_t err;
    char err_buf[128u];
    const char* err_ctx;

    // The JSON text we are interpreting.
    const char* json = "{\"sensor-id\":\"aa-xx-142b\",\"kelvin\":296.549988}";
    ah_buf_t src = ah_buf_from((uint8_t*) json, (uint32_t) strlen(json));

    // Parsing the JSON text populates `buf`.
    ah_json_buf_t buf = { 0u };
    err = ah_json_parse(src, &buf);
    if (err != AH_ENONE) {
        err_ctx = "ah_json_parse()";
        goto handle_err;
    }

    // We use these to ensure the object we expect contains all mandatory fields.
    bool has_sensor_id = false;
    bool has_kelvin = false;

    // We use these to collect the data in the object.
    char sensor_id[16u] = { 0u };
    float kelvin = -1.0f;

    // We begin validation by ensuring that a root value of the object type exists in `buf`.
    if (buf.length == 0u || buf.values[0u].type != AH_JSON_TYPE_OBJECT) {
        err = AH_EINVAL;
        err_ctx = "'expecting object at root'";
        goto handle_err;
    }

    // We then iterate through the children of the object.
    for (size_t i = 1u; i < buf.length; i += 1u) {
        ah_json_val_t* val = &buf.values[i];

        // As long as the level is unchanged, the current value is going to be a
        // string and the next value is guaranteed to have the same level. Why?
        // Because we know that there is an object at level 0u, and objects are
        // guaranteed to always have even numbers of child values where even
        // children (beginning with the 0th child) is a key of type string.
        if (val->level != 1u) {
            continue;
        }

        // Is the key string equal to "sensor-id"? If so, make sure we have not
        // seen a sensor-id before and that the next value is of type string.
        // Save that value to the `sensor_id` variable. To improve performance,
        // you may choose to use memcmp() directly instead of
        // ah_json_str_compare(). This requires the sender not to use any escape
        // sequences in this particular key, however.
        if (ah_json_str_compare("sensor-id", 9u, val->base, val->length) == 0u) {
            if (has_sensor_id) {
                err = AH_EDUP;
                err_ctx = "ah_json_str_compare()";
                goto handle_err;
            }

            i += 1u;

            val = &buf.values[i];
            if (val->type != AH_JSON_TYPE_STRING) {
                err = AH_EINVAL;
                err_ctx = "'expecting \"sensor-id\" to have string value'";
                goto handle_err;
            }

            size_t sensor_id_length = sizeof(sensor_id);
            err = ah_json_str_unescape(val->base, val->length, sensor_id, &sensor_id_length);
            if (err != AH_ENONE) {
                err_ctx = "ah_json_str_unescape()";
                goto handle_err;
            }
            if (sensor_id_length == sizeof(sensor_id)) {
                sensor_id_length -= 1u;
            }
            sensor_id[sensor_id_length] = '\0';

            has_sensor_id = true;
            continue;
        }

        // Is the key string equal to "kelvin"? If so, make sure we have not
        // seen a kelvin key before and that the next value is of type number.
        // Parse that value to the `kelvin` variable.
        if (ah_json_str_compare("kelvin", 6u, val->base, val->length) == 0u) {
            if (has_kelvin) {
                err = AH_EDUP;
                err_ctx = "ah_json_str_compare()";
                goto handle_err;
            }

            i += 1u;

            val = &buf.values[i];
            if (val->type != AH_JSON_TYPE_NUMBER) {
                err = AH_EINVAL;
                err_ctx = "'expecting \"kelvin\" to have number value'";
                goto handle_err;
            }

            errno = 0;
            kelvin = strtof(val->base, NULL);
            if (errno != 0) {
                err = errno;
                err_ctx = "strtof";
                goto handle_err;
            }

            has_kelvin = true;
            continue;
        }
    }

    // Make sure we have seen all mandatory fields.

    if (!has_sensor_id) {
        err = AH_EINVAL;
        err_ctx = "'expecting \"sensor_id\" in object'";
        goto handle_err;
    }

    if (!has_kelvin) {
        err = AH_EINVAL;
        err_ctx = "'expecting \"kelvin\" in object'";
        goto handle_err;
    }

    // Print the result, if everything worked out as expected.

    printf("Interpretation result:\n"
           "\tsensor_id: %15s\n"
           "\tkelvin:    %15f\n",
        sensor_id, kelvin);

    exit(EXIT_SUCCESS);

handle_err:
    ah_strerror_r(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "%s failed: %s\n", err_ctx, err_buf);
    exit(EXIT_FAILURE);
}
