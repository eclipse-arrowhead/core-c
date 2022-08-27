// SPDX-License-Identifier: EPL-2.0

#ifndef AH_UNIT_H_
#define AH_UNIT_H_

#include <ah/defs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AH_UNIT_CTX \
 ((ah_unit_ctx_t) { .file = __FILE__, .line = __LINE__ })

typedef struct ah_unit_ctx ah_unit_ctx_t;
typedef struct ah_unit_res ah_unit_res_t;

struct ah_unit_ctx {
    const char* file;
    int line;
};

struct ah_unit_res {
    int assertion_count;
    int fail_count;
};

bool ah_unit_assert(ah_unit_ctx_t ctx, ah_unit_res_t* res, bool is_success, const char* format, ...);
bool ah_unit_assert_eq_cstr(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* actual, const char* expected);
bool ah_unit_assert_eq_enum(ah_unit_ctx_t ctx, ah_unit_res_t* res, int actual, int expected, const char* (*to_str)(int) );
bool ah_unit_assert_eq_err(ah_unit_ctx_t ctx, ah_unit_res_t* res, ah_err_t actual, ah_err_t expected);
bool ah_unit_assert_eq_mem(ah_unit_ctx_t ctx, ah_unit_res_t* res, const void* actual, const void* expected, size_t size);
bool ah_unit_assert_eq_intmax(ah_unit_ctx_t ctx, ah_unit_res_t* res, intmax_t actual, intmax_t expected);
bool ah_unit_assert_eq_str(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* actual, size_t actual_length, const char* expected, size_t expected_length);
bool ah_unit_assert_eq_uintmax(ah_unit_ctx_t ctx, ah_unit_res_t* res, uintmax_t actual, uintmax_t expected);
void ah_unit_print(ah_unit_ctx_t ctx, const char* format, ...);
void ah_unit_print_results(const ah_unit_res_t* res);
void ah_unit_fail(ah_unit_ctx_t ctx, ah_unit_res_t* res, const char* format, ...);
void ah_unit_pass(ah_unit_res_t* res);

#endif
