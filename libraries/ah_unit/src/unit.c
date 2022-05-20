// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/unit.h"

#include <ah/err.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void ah_unit_print_results(const struct ah_unit* unit)
{
    if (unit == NULL) {
        (void) fputs("Failed to print results; unit == NULL\n", stderr);
        return;
    }

    if (unit->fail_count == 0) {
        (void) printf("Passed all %d executed assertions.\n", unit->assertion_count);
    }
    else {
        (void) printf("\nFailed %d out of %d executed assertions!\n", unit->fail_count, unit->assertion_count);
    }
}

bool ah_i_unit_assert(struct ah_i_unit unit, bool is_success, const char* message)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (is_success) {
        return true;
    }

    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) %s\n", unit.func, unit.file, unit.line, message);

    return false;
}

bool ah_i_unit_assertf(struct ah_i_unit unit, bool is_success, const char* format, ...)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }
    if (format == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; format == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (is_success) {
        return true;
    }

    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) ", unit.func, unit.file, unit.line);

    va_list args;
    va_start(args, format);
    (void) vprintf(format, args);
    va_end(args);

    (void) putchar('\n');

    return false;
}

bool ah_i_unit_assert_cstr_eq(struct ah_i_unit unit, const char* a, const char* b, const char* message)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (a == b) {
        return true;
    }
    if (a == NULL || b == NULL) {
        goto fail;
    }
    if (strcmp(a, b) == 0) {
        return true;
    }

fail:
    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) %s\n\t\"%s\" != \"%s\"\n", unit.func, unit.file, unit.line, message, a, b);

    return false;
}

bool ah_i_unit_assert_enum_eq(struct ah_i_unit unit, int a, int b, const char* (*tostr_cb)(int) )
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }
    if (tostr_cb == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; tostr_cb == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (a == b) {
        return true;
    }

    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) [%s] != [%s]; %d != %d\n", unit.func, unit.file, unit.line, tostr_cb(a), tostr_cb(b),
        a, b);

    return false;
}

bool ah_i_unit_assert_err_eq(struct ah_i_unit unit, ah_err_t a, ah_err_t b, const char* message)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (a == b) {
        return true;
    }

    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) [%s] != [%s]; %d != %d\n\t%s\n", unit.func, unit.file, unit.line, ah_strerror(a),
        ah_strerror(b), a, b, message);

    return false;
}

bool ah_i_unit_assert_mem_eq(struct ah_i_unit unit, const void* a_, const void* b_, size_t size, const char* message)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    const unsigned char* a = a_;
    const unsigned char* b = b_;

    unit.external->assertion_count += 1;

    if (memcmp(a, b, size) == 0) {
        return true;
    }

    unit.external->fail_count += 1;
    (void) printf("FAIL %s (%s:%d) %s\n\t", unit.func, unit.file, unit.line, message);

    const unsigned char* a_end = &a[size];
    for (; a != a_end; a = &a[1]) {
        (void) printf("%02X", *a);
    }

    (void) printf(" !=\n\t");

    const unsigned char* b_end = &b[size];
    for (; b != b_end; b = &b[1]) {
        (void) printf("%02X", *b);
    }

    (void) putchar('\n');

    return false;
}

bool ah_i_unit_assert_signed_eq(struct ah_i_unit unit, intmax_t a, intmax_t b, const char* message)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (a == b) {
        return true;
    }

    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) %s; %" PRIiMAX " != %" PRIiMAX "\n", unit.func, unit.file, unit.line, message, a, b);

    return false;
}

bool ah_i_unit_assert_unsigned_eq(struct ah_i_unit unit, uintmax_t a, uintmax_t b, const char* message)
{
    if (unit.external == NULL) {
        (void) fprintf(stderr, "FAIL %s (%s:%d) Bad assertion; unit == NULL\n", unit.func, unit.file, unit.line);
        return false;
    }

    unit.external->assertion_count += 1;

    if (a == b) {
        return true;
    }

    unit.external->fail_count += 1;

    (void) printf("FAIL %s (%s:%d) %s; %" PRIuMAX " != %" PRIuMAX "\n", unit.func, unit.file, unit.line, message, a, b);

    return false;
}
