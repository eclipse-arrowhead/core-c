// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/alloc.h>
#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>
#include <ah/utf8.h>
#include <stdlib.h>

struct s_parser {
    const uint8_t* src_off;
    const uint8_t* src_end;
    bool is_realloc_enabled;
};

static ah_err_t s_parse_value(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);

static ah_err_t s_parse_object(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);
static ah_err_t s_parse_array(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);
static ah_err_t s_parse_string(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);
static ah_err_t s_parse_number(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);
static ah_err_t s_parse_keyword(struct s_parser* parser, ah_json_val_t* parent, const char* chars, uint16_t type, uint16_t level, ah_json_buf_t* dst);

static ah_err_t s_report_error(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, size_t length, ah_json_buf_t* dst);

static ah_err_t s_alloc_value(struct s_parser* parser, ah_json_val_t* parent, uint16_t type, uint16_t level, ah_json_buf_t* dst, ah_json_val_t** out);

static uint8_t s_peek_byte_or_zero(struct s_parser* parser);
static uint8_t s_peek_byte_or_zero_at_offset(struct s_parser* parser, uintptr_t offset);
static void s_skip_byte(struct s_parser* parser);
static size_t s_skip_if_chars(struct s_parser* parser, const char* chars);
static bool s_skip_n_bytes(struct s_parser* parser, size_t n);
static bool s_skip_while_digits(struct s_parser* parser);
static void s_skip_whitespace(struct s_parser* parser);

ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst)
{
    if ((src.base == NULL && src.size != 0u) || dst == NULL || dst->length > dst->capacity) {
        return AH_EINVAL;
    }

    struct s_parser parser = {
        .src_off = src.base,
        .src_end = &src.base[src.size],
        .is_realloc_enabled = false,
    };

    if (dst->values == NULL) {
        if (dst->length != 0u) {
            return AH_EINVAL;
        }
        parser.is_realloc_enabled = true;
    }

    if (!ah_utf8_validate((const char*) src.base, src.size)) {
        return AH_ESYNTAX;
    }

    s_skip_whitespace(&parser);

    ah_err_t err = s_parse_value(&parser, NULL, 0u, dst);
    if (err != AH_ENONE) {
        return err;
    }

    s_skip_whitespace(&parser);

    if (parser.src_off != parser.src_end) {
        return s_report_error(&parser, NULL, 0u, 1u, dst);
    }

    return AH_ENONE;
}

static ah_err_t s_parse_value(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    switch (s_peek_byte_or_zero(parser)) {
    case '\0':
        return AH_EEOF;

    case '{':
        return s_parse_object(parser, parent, level, dst);

    case '[':
        return s_parse_array(parser, parent, level, dst);

    case '"':
        return s_parse_string(parser, parent, level, dst);

    case 't':
        return s_parse_keyword(parser, parent, "true", AH_JSON_TYPE_TRUE, level, dst);

    case 'f':
        return s_parse_keyword(parser, parent, "false", AH_JSON_TYPE_FALSE, level, dst);

    case 'n':
        return s_parse_keyword(parser, parent, "null", AH_JSON_TYPE_NULL, level, dst);

    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return s_parse_number(parser, parent, level, dst);

    default:
        return s_report_error(parser, parent, level, 1u, dst);
    }
}

static ah_err_t s_parse_object(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    if (level >= AH_JSON_LEVEL_MAX) {
        return AH_EOVERFLOW;
    }
    uint16_t child_level = level + 1u;

    ah_err_t err;

    ah_json_val_t* object;
    err = s_alloc_value(parser, parent, AH_JSON_TYPE_OBJECT, level, dst, &object);
    if (err != AH_ENONE) {
        return err;
    }

    ah_assert_if_debug(s_peek_byte_or_zero(parser) == '{');
    s_skip_byte(parser);
    s_skip_whitespace(parser);

    if (s_peek_byte_or_zero(parser) == '}') {
        s_skip_byte(parser);
        return AH_ENONE;
    }

    for (;;) {
        switch (s_peek_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case '"':
            break;

        default:
            goto report_error;
        }

        err = s_parse_string(parser, object, child_level, dst);
        if (err != AH_ENONE) {
            return err;
        }

        s_skip_whitespace(parser);

        switch (s_peek_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ':':
            s_skip_byte(parser);
            break;

        default:
            goto report_error;
        }

        s_skip_whitespace(parser);

        err = s_parse_value(parser, object, child_level, dst);
        if (err != AH_ENONE) {
            return err;
        }

        s_skip_whitespace(parser);

        switch (s_peek_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ',':
            s_skip_byte(parser);
            s_skip_whitespace(parser);
            continue;

        case '}':
            s_skip_byte(parser);
            return AH_ENONE;

        default:
            goto report_error;
        }
    }

report_error:
    return s_report_error(parser, object, child_level, 1u, dst);
}

static ah_err_t s_parse_array(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    if (level >= AH_JSON_LEVEL_MAX) {
        return AH_EOVERFLOW;
    }
    uint16_t child_level = level + 1u;

    ah_err_t err;

    ah_json_val_t* array;
    err = s_alloc_value(parser, parent, AH_JSON_TYPE_ARRAY, level, dst, &array);
    if (err != AH_ENONE) {
        return err;
    }

    ah_assert_if_debug(s_peek_byte_or_zero(parser) == '[');
    s_skip_byte(parser);
    s_skip_whitespace(parser);

    if (s_peek_byte_or_zero(parser) == ']') {
        s_skip_byte(parser);
        return AH_ENONE;
    }

    for (;;) {
        err = s_parse_value(parser, array, child_level, dst);
        if (err != AH_ENONE) {
            return err;
        }

        s_skip_whitespace(parser);

        switch (s_peek_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ',':
            s_skip_byte(parser);
            s_skip_whitespace(parser);
            continue;

        case ']':
            s_skip_byte(parser);
            return AH_ENONE;

        default:
            return s_report_error(parser, array, child_level, 1u, dst);
        }
    }
}

static ah_err_t s_parse_string(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    ah_assert_if_debug(s_peek_byte_or_zero(parser) == '"');
    s_skip_byte(parser);

    ah_err_t err;

    ah_json_val_t* string;
    err = s_alloc_value(parser, parent, AH_JSON_TYPE_STRING, level, dst, &string);
    if (err != AH_ENONE) {
        return err;
    }

    size_t length = 0u;

    for (;;) {
        switch (s_peek_byte_or_zero(parser)) {
        case '\0':
            err = AH_EEOF;
            goto handle_done;

        case '"':
            s_skip_byte(parser);
            goto handle_done;

        case '\\':
            switch (s_peek_byte_or_zero_at_offset(parser, 1u)) {
            case '\0':
                err = AH_EEOF;
                goto handle_done;

            case '"':
            case '\\':
            case '/':
            case 'b':
            case 'f':
            case 'n':
            case 'r':
            case 't':
                if (ah_math_add_size(length, 2u, &length) != AH_ENONE) {
                    err = AH_EOVERFLOW;
                    goto handle_done;
                }
                if (!s_skip_n_bytes(parser, 2u)) {
                    err = AH_EOVERFLOW;
                    goto handle_done;
                }
                break;

            case 'u':
                for (size_t i = 2u; i < 6u; i += 1u) {
                    uint8_t ch = parser->src_off[i];
                    if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f')) {
                        continue;
                    }
                    err = s_report_error(parser, parent, level, i, dst);
                    goto handle_done;
                }

                if (ah_math_add_size(length, 6u, &length) != AH_ENONE) {
                    err = AH_EOVERFLOW;
                    goto handle_done;
                }
                if (!s_skip_n_bytes(parser, 6u)) {
                    err = AH_EOVERFLOW;
                    goto handle_done;
                }
                break;

            default:
                err = s_report_error(parser, parent, level, 2u, dst);
                goto handle_done;
            }
            break;

        default:
            if (ah_math_add_size(length, 1u, &length) != AH_ENONE) {
                err = AH_EOVERFLOW;
                goto handle_done;
            }
            s_skip_byte(parser);
            break;
        }
    }

handle_done:

#if SIZE_MAX < AH_JSON_LENGTH_MAX
    if (length > AH_JSON_LENGTH_MAX && err == AH_ENONE) {
        err = AH_EOVERFLOW;
    }
#endif

    if (err == AH_EOVERFLOW) {
        length = AH_JSON_LENGTH_MAX;
    }

    string->length = length;

    return err;
}

static ah_err_t s_parse_number(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    ah_err_t err;

    ah_json_val_t* number;
    err = s_alloc_value(parser, parent, AH_JSON_TYPE_NUMBER, level, dst, &number);
    if (err != AH_ENONE) {
        return err;
    }

    err = AH_ENONE;

    if (s_peek_byte_or_zero(parser) == '-') {
        s_skip_byte(parser);
    }

    if (s_peek_byte_or_zero(parser) == '0') {
        s_skip_byte(parser);

        switch (s_peek_byte_or_zero(parser)) {
        case '\0':
            goto handle_done;

        case '.':
            goto parse_fraction;

        case 'E':
        case 'e':
            goto parse_exponent;

        default:
            s_skip_byte(parser);
            number->type = AH_JSON_TYPE_ERROR;
            err = AH_ESYNTAX;
            goto handle_done;
        }
    }

    if (!s_skip_while_digits(parser)) {
        err = AH_EEOF;
        goto handle_done;
    }

    switch (s_peek_byte_or_zero(parser)) {
    case 'E':
    case 'e':
        goto parse_exponent;

    case '.':
        goto parse_fraction;

    default:
        goto handle_done;
    }

parse_fraction:
    s_skip_byte(parser);

    if (!s_skip_while_digits(parser)) {
        err = AH_EEOF;
        goto handle_done;
    }

    switch (s_peek_byte_or_zero(parser)) {
    case 'E':
    case 'e':
        goto parse_exponent;

    default:
        goto handle_done;
    }

parse_exponent:
    s_skip_byte(parser);

    switch (s_peek_byte_or_zero(parser)) {
    case '+':
    case '-':
        s_skip_byte(parser);
        break;

    default:
        break;
    }

    if (!s_skip_while_digits(parser)) {
        err = AH_EEOF;
        goto handle_done;
    }

    ptrdiff_t length;

handle_done:
    length = parser->src_off - (const uint8_t*) number->base;

    if (ah_unlikely(length < 0 || (((uintmax_t) length) > AH_JSON_LENGTH_MAX))) {
        if (err == AH_ENONE) {
            return AH_EOVERFLOW;
        }
        length = AH_JSON_LENGTH_MAX;
    }

    number->length = length;

    return err;
}

static ah_err_t s_parse_keyword(struct s_parser* parser, ah_json_val_t* parent, const char* chars, uint16_t type, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    ah_json_val_t* val;

    ah_err_t err = s_alloc_value(parser, parent, type, level, dst, &val);
    if (err != AH_ENONE) {
        return err;
    }

    size_t n_read_chars = s_skip_if_chars(parser, chars);
    if (n_read_chars == 0u) {
        val->type = AH_JSON_TYPE_ERROR;
        val->length = 1u;
        return AH_ESYNTAX;
    }

    val->length = n_read_chars;

    return AH_ENONE;
}

static ah_err_t s_report_error(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, size_t length, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(length <= AH_JSON_LENGTH_MAX);
    ah_assert_if_debug(dst != NULL);

    ah_json_val_t* val;

    ah_err_t err = s_alloc_value(parser, parent, AH_JSON_TYPE_ERROR, level, dst, &val);
    if (err != AH_ENONE) {
        return err;
    }

    val->length = length;

    return AH_ESYNTAX;
}

static ah_err_t s_alloc_value(struct s_parser* parser, ah_json_val_t* parent, uint16_t type, uint16_t level, ah_json_buf_t* dst, ah_json_val_t** out)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);
    ah_assert_if_debug(out != NULL);

    if (dst->length == dst->capacity) {
        if (!parser->is_realloc_enabled) {
            return AH_ENOBUFS;
        }

        size_t new_capacity_in_values;
        if (dst->capacity < 8u) {
            new_capacity_in_values = 8u;
        }
        else {
            if (ah_math_add_size(dst->capacity, dst->capacity / 2u, &new_capacity_in_values) != AH_ENONE) {
                return AH_ENOMEM;
            }
        }

        size_t new_capacity_in_bytes;
        if (ah_math_mul_size(new_capacity_in_values, sizeof(ah_json_val_t), &new_capacity_in_bytes) != AH_ENONE) {
            return AH_ENOMEM;
        }

        ah_json_val_t* new_values = ah_realloc(dst->values, new_capacity_in_bytes);
        if (new_values == NULL) {
            return AH_ENOMEM;
        }

        dst->capacity = new_capacity_in_values;
        dst->values = new_values;
    }

    ah_json_val_t* val = &dst->values[dst->length];

    *val = (ah_json_val_t) {
        .base = (const char*) parser->src_off,
        .type = type,
        .level = level,
        .length = 0u,
    };

    *out = val;
    dst->length += 1u;

    if (ah_likely(parent != NULL)) {
        ah_assert_if_debug(parent->type == AH_JSON_TYPE_OBJECT || parent->type == AH_JSON_TYPE_ARRAY);

        if (parent->length >= AH_JSON_LENGTH_MAX) {
            return AH_EOVERFLOW;
        }

        parent->length += 1u;
    }

    return AH_ENONE;
}

static uint8_t s_peek_byte_or_zero(struct s_parser* parser)
{
    ah_assert_if_debug(parser != NULL);

    if (parser->src_off == parser->src_end) {
        return '\0';
    }

    return *parser->src_off;
}

static uint8_t s_peek_byte_or_zero_at_offset(struct s_parser* parser, uintptr_t offset)
{
    ah_assert_if_debug(parser != NULL);

    uintptr_t off;
    if (ah_math_add_uintptr((uintptr_t) parser->src_off, offset, &off) != AH_ENONE) {
        return '\0';
    }
    if ((const uint8_t*) off > parser->src_end) {
        return '\0';
    }

    return ((const uint8_t*) off)[0u];
}

static void s_skip_byte(struct s_parser* parser)
{
    if (parser->src_off == parser->src_end) {
        return;
    }

    parser->src_off = &parser->src_off[1u];
}

static size_t s_skip_if_chars(struct s_parser* parser, const char* chars)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(chars != NULL);

    for (size_t i = 0u;; i += 1u) {
        char ch = chars[i];

        if (ch == '\0') {
            parser->src_off = &parser->src_off[i];
            return i;
        }

        if (&parser->src_off[i] >= parser->src_end) {
            return 0u;
        }

        if (ch != parser->src_off[i]) {
            return 0u;
        }
    }
}

static bool s_skip_n_bytes(struct s_parser* parser, size_t n)
{
    ah_assert_if_debug(parser != NULL);

#if SIZE_MAX > UINTPTR_MAX
    if (n > UINTPTR_MAX) {
        return false;
    }
#endif

    uintptr_t off;
    if (ah_math_add_uintptr((uintptr_t) parser->src_off, n, &off) != AH_ENONE) {
        return false;
    }
    if ((const uint8_t*) off > parser->src_end) {
        return false;
    }

    parser->src_off = (const uint8_t*) off;
    return true;
}

static bool s_skip_while_digits(struct s_parser* parser)
{
    ah_assert_if_debug(parser != NULL);

    bool has_digits = false;

    while (parser->src_off != parser->src_end) {
        uint8_t ch = parser->src_off[0u];
        if (ch < '0' || ch > '9') {
            break;
        }

        has_digits = true;

        parser->src_off = &parser->src_off[1u];
    }

    return has_digits;
}

static void s_skip_whitespace(struct s_parser* parser)
{
    ah_assert_if_debug(parser != NULL);

    for (;;) {
        uint8_t byte = s_peek_byte_or_zero(parser);
        if (byte != 0x09 && byte != 0x0A && byte != 0x0D && byte != 0x20) {
            break;
        }
        s_skip_byte(parser);
    }
}
