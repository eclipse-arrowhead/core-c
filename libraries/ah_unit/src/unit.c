// SPDX-License-Identifier: EPL-2.0

#include "ah/unit.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void s_fail(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* format, va_list args);
static void s_print(ah_unit_ctx_t ctx, const char* format, va_list args);

bool ah_unit_assert(ah_unit_ctx_t ctx, ah_unit_res_t* res, bool is_success, const char* format, ...)
{
    if (is_success) {
        ah_unit_pass(res);
        return true;
    }

    va_list args;
    va_start(args, format);
    s_fail(ctx, res, format, args);
    va_end(args);

    return false;
}

bool ah_unit_assert_eq_cstr(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* actual, const char* expected)
{
    if (actual == expected) {
        goto pass;
    }
    if (actual == NULL || expected == NULL) {
        goto fail;
    }
    if (strcmp(actual, expected) != 0) {
        goto fail;
    }

pass:
    ah_unit_pass(res);
    return true;

fail:
    ah_unit_fail(ctx, res, "got `%s`; expected `%s`", actual, expected);
    return false;
}

bool ah_unit_assert_eq_enum(ah_unit_ctx_t ctx, ah_unit_res_t* res, int actual, int expected, const char* (*to_str)(int) )
{
    ah_assert_always(res != NULL);
    ah_assert_always(to_str != NULL);

    if (actual == expected) {
        ah_unit_pass(res);
        return true;
    }

    ah_unit_fail(ctx, res, "got `%s` (%d); expected `%s` (%d)", to_str(actual), actual, to_str(expected), expected);
    return false;
}

bool ah_unit_assert_eq_err(ah_unit_ctx_t ctx, ah_unit_res_t* res, ah_err_t actual, ah_err_t expected)
{
    ah_assert_always(res != NULL);

    if (actual == expected) {
        ah_unit_pass(res);
        return true;
    }

    char actual_buf[128u];
    ah_strerror_r(actual, actual_buf, sizeof(actual_buf));

    char expected_buf[128u];
    ah_strerror_r(expected, expected_buf, sizeof(expected_buf));

    ah_unit_fail(ctx, res, "got `%s` (%d); expected `%s` (%d)", actual_buf, actual, expected_buf, expected);
    return false;
}

bool ah_unit_assert_eq_mem(ah_unit_ctx_t ctx, ah_unit_res_t* res, const void* actual_, const void* expected_, size_t size)
{
    ah_assert_always(res != NULL);

    const unsigned char* actual = actual_;
    const unsigned char* expected = expected_;

    if (memcmp(actual, expected, size) == 0) {
        ah_unit_pass(res);
        return true;
    }

    char actual_buf[128u];
    const unsigned char* actual_end = &actual[size];
    size_t actual_i = 0u;
    while (actual_i < sizeof(actual_buf) - 4u && actual != actual_end) {
        (void) snprintf(&actual_buf[actual_i], 4u, "%02X ", actual[0u]);
        actual_i += 3u;
        actual = &actual[1];
    }
    if (actual_i >= sizeof(actual_buf) - 4u) {
        memcpy(&actual_buf[sizeof(actual_buf) - 4u], "...", 4);
    }

    char expected_buf[128u];
    const unsigned char* expected_end = &expected[size];
    size_t expected_i = 0u;
    while (expected_i < sizeof(expected_buf) - 4u && expected != expected_end) {
        (void) snprintf(&expected_buf[expected_i], 4u, "%02X ", expected[0u]);
        expected_i += 3u;
        expected = &expected[1];
    }
    if (expected_i >= sizeof(expected_buf) - 4u) {
        memcpy(&expected_buf[sizeof(expected_buf) - 4u], "...", 4);
    }

    ah_unit_fail(ctx, res, "got %s; expected %s", actual_buf, expected_buf);
    return false;
}

bool ah_unit_assert_eq_intmax(ah_unit_ctx_t ctx, ah_unit_res_t* res, intmax_t actual, intmax_t expected)
{
    ah_assert_always(res != NULL);

    if (actual == expected) {
        ah_unit_pass(res);
        return true;
    }

    ah_unit_fail(ctx, res, "got %" PRIiMAX "; expected %" PRIiMAX, actual, expected);
    return false;
}

bool ah_unit_assert_eq_str(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* actual, size_t actual_length, const char* expected, size_t expected_length)
{
    if (actual == expected) {
        goto pass;
    }
    if (actual == NULL || expected == NULL) {
        goto fail;
    }
    if (actual_length != expected_length) {
        goto fail;
    }
    if (memcmp(actual, expected, expected_length) != 0) {
        goto fail;
    }

pass:
    ah_unit_pass(res);
    return true;

fail:
    ah_unit_fail(ctx, res, "got `%s`; expected `%s`", actual, expected);
    return false;
}

bool ah_unit_assert_eq_uintmax(ah_unit_ctx_t ctx, ah_unit_res_t* res, uintmax_t actual, uintmax_t expected)
{
    ah_assert_always(res != NULL);

    if (actual == expected) {
        ah_unit_pass(res);
        return true;
    }

    ah_unit_fail(ctx, res, "got %" PRIuMAX "; expected %" PRIuMAX, actual, expected);
    return false;
}

void ah_unit_print(ah_unit_ctx_t ctx, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    s_print(ctx, format, args);
    va_end(args);
}

void ah_unit_print_results(const struct ah_unit_res* res)
{
    ah_assert_always(res != NULL);

    if (res->fail_count == 0) {
        (void) printf("Passed all %d executed assertions.\n", res->assertion_count);
    }
    else {
        (void) fprintf(stderr, "Failed %d out of %d executed assertions!\n", res->fail_count, res->assertion_count);
    }
}

void ah_unit_fail(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    s_fail(ctx, res, format, args);
    va_end(args);
}

void ah_unit_pass(ah_unit_res_t* res)
{
    ah_assert_always(res != NULL);

    res->assertion_count += 1u;
}

static void s_fail(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* format, va_list args)
{
    ah_assert_always(res != NULL);

    res->assertion_count += 1u;
    res->fail_count += 1u;

    (void) fputs("FAIL ", stderr);

    s_print(ctx, format, args);
}

static void s_print(ah_unit_ctx_t ctx, const char* format, va_list args)
{
    (void) fprintf(stderr, "%s:%d ", ctx.file, ctx.line);
    (void) vfprintf(stderr, format, args);
    (void) fputc('\n', stderr);
}
