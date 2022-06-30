// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UNIT_H_
#define AH_UNIT_H_

#include "internal/_unit.h"

#define ah_unit_assert(unit, is_success, message) \
 ah_i_unit_assert(AH_I_UNIT_WRAP(unit), (is_success), (message))

#define ah_unit_assertf(unit, is_success, format, ...) \
 ah_i_unit_assertf(AH_I_UNIT_WRAP(unit), (is_success), (format), __VA_ARGS__)

#define ah_unit_assert_cstr_eq(unit, a, b) \
 ah_i_unit_assert_cstr_eq(AH_I_UNIT_WRAP(unit), (a), (b), #a " != " #b)

#define ah_unit_assert_enum_eq(unit, a, b, tostr_cb) \
 ah_i_unit_assert_enum_eq(AH_I_UNIT_WRAP(unit), (a), (b), (tostr_cb))

#define ah_unit_assert_err_eq(unit, a, b) \
 ah_i_unit_assert_err_eq(AH_I_UNIT_WRAP(unit), (a), (b), #a " != " #b)

#define ah_unit_assert_mem_eq(unit, a, b, size) \
 ah_i_unit_assert_mem_eq(AH_I_UNIT_WRAP(unit), (a), (b), (size), #a " != " #b)

#define ah_unit_assert_signed_eq(unit, a, b) \
 ah_i_unit_assert_signed_eq(AH_I_UNIT_WRAP(unit), (intmax_t) (a), (intmax_t) (b), #a " != " #b)

#define ah_unit_assert_unsigned_eq(unit, a, b) \
 ah_i_unit_assert_unsigned_eq(AH_I_UNIT_WRAP(unit), (uintmax_t) (a), (uintmax_t) (b), #a " != " #b)

#define ah_unit_fail(unit, message) \
 ((void) ah_i_unit_assert(AH_I_UNIT_WRAP(unit), false, (message)))

#define ah_unit_failf(unit, format, ...) \
 ((void) ah_i_unit_assertf(AH_I_UNIT_WRAP(unit), false, (format), __VA_ARGS__))

#define ah_unit_pass(unit)      \
 do {                           \
  (unit)->assertion_count += 1; \
 } while (false)

#define ah_unit_print(unit, message) \
 ah_i_unit_print(AH_I_UNIT_WRAP(unit), (message))

#define ah_unit_printf(unit, format, ...) \
 ah_i_unit_printf(AH_I_UNIT_WRAP(unit), (format), __VA_ARGS__)

#define AH_I_UNIT_WRAP(UNIT) \
 ((struct ah_i_unit) { .external = (UNIT), .file = __FILE__, .line = __LINE__, .func = __func__ })

typedef struct ah_unit ah_unit_t;

struct ah_unit {
    int assertion_count;
    int fail_count;
};

void ah_unit_print_results(const ah_unit_t* unit);

#endif
