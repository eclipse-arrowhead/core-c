// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_UNIT_H_
#define AH_INTERNAL_UNIT_H_

#include <ah/defs.h>
#include <ah/str.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ah_i_unit {
    struct ah_unit* external;

    const char* file;
    int line;
    const char* func;
};

bool ah_i_unit_assert(struct ah_i_unit unit, bool is_success, const char* message);
bool ah_i_unit_assertf(struct ah_i_unit unit, bool is_success, const char* format, ...);
bool ah_i_unit_assert_cstr_eq(struct ah_i_unit unit, const char* a, const char* b, const char* message);
bool ah_i_unit_assert_enum_eq(struct ah_i_unit unit, int a, int b, const char* (*tostr_cb)(int) );
bool ah_i_unit_assert_err_eq(struct ah_i_unit unit, ah_err_t a, ah_err_t b, const char* message);
bool ah_i_unit_assert_mem_eq(struct ah_i_unit unit, const void* a, const void* b, size_t size, const char* message);
bool ah_i_unit_assert_signed_eq(struct ah_i_unit unit, intmax_t a, intmax_t b, const char* message);
bool ah_i_unit_assert_str_eq(struct ah_i_unit unit, ah_str_t a, ah_str_t b, const char* message);
bool ah_i_unit_assert_unsigned_eq(struct ah_i_unit unit, uintmax_t a, uintmax_t b, const char* message);

#endif
