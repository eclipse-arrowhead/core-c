// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/json.h"

#include <ah/assert.h>
#include <ah/err.h>
#include <ah/math.h>
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
static ah_err_t s_parse_true(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);
static ah_err_t s_parse_false(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);
static ah_err_t s_parse_null(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);

static ah_err_t s_report_error(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst);

static ah_err_t s_alloc_value(struct s_parser* parser, ah_json_val_t* parent, uint16_t type, uint16_t level, ah_json_buf_t* dst, ah_json_val_t** out);

static uint8_t s_peek_byte_or_zero(struct s_parser* parser);
static uint8_t s_read_byte_or_zero(struct s_parser* parser);
static void s_skip_byte(struct s_parser* parser);
static void s_skip_if_char(struct s_parser* parser, char ch);
static void s_skip_whitespace(struct s_parser* parser);

ah_extern ah_err_t ah_json_parse(ah_buf_t src, ah_json_buf_t* dst)
{
    if ((src.base == NULL && src.size != 0u) || dst == NULL) {
        return AH_EINVAL;
    }

    struct s_parser parser = {
        .src_off = src.base,
        .src_end = &src.base[src.size],
        .is_realloc_enabled = dst->values == NULL,
    };

    ah_err_t err = s_parse_value(&parser, NULL, 0u, dst);
    if (err != AH_ENONE) {
        return err;
    }

    s_skip_whitespace(&parser);

    if (parser.src_off != parser.src_end) {
        return s_report_error(&parser, NULL, 0u, dst);
    }

    return AH_ENONE;
}

static ah_err_t s_parse_value(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    s_skip_whitespace(parser);

    switch (s_read_byte_or_zero(parser)) {
    case '\0':
        return AH_ENONE;

    case '{':
        return s_parse_object(parser, parent, level, dst);

    case '[':
        return s_parse_array(parser, parent, level, dst);

    case '"':
        return s_parse_string(parser, parent, level, dst);

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

    case 't':
        return s_parse_true(parser, parent, level, dst);

    case 'f':
        return s_parse_false(parser, parent, level, dst);

    case 'n':
        return s_parse_null(parser, parent, level, dst);

    default:
        return s_report_error(parser, parent, level, dst);
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

    for (;;) {
        s_skip_whitespace(parser);

        switch (s_read_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case '"':
            break;

        case '}':
            return AH_ENONE;

        default:
            goto report_error;
        }

        err = s_parse_string(parser, object, child_level, dst);
        if (err != AH_ENONE) {
            return err;
        }

        s_skip_whitespace(parser);

        switch (s_read_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ':':
            break;

        default:
            goto report_error;
        }

        err = s_parse_value(parser, object, child_level, dst);
        if (err != AH_ENONE) {
            return err;
        }

        s_skip_whitespace(parser);

        switch (s_read_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ',':
            break;

        case '}':
            return AH_ENONE;

        default:
            goto report_error;
        }
    }

report_error:
    return s_report_error(parser, object, child_level, dst);
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

    for (;;) {
        s_skip_whitespace(parser);

        switch (s_read_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ']':
            return AH_ENONE;

        default:
            break;
        }

        err = s_parse_value(parser, array, child_level, dst);
        if (err != AH_ENONE) {
            return err;
        }

        s_skip_whitespace(parser);

        switch (s_read_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case ',':
            break;

        case ']':
            return AH_ENONE;

        default:
            return s_report_error(parser, array, child_level, dst);
        }
    }
}

static ah_err_t s_parse_string(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    ah_err_t err;

    ah_json_val_t* string;
    err = s_alloc_value(parser, parent, AH_JSON_TYPE_STRING, level, dst, &string);
    if (err != AH_ENONE) {
        return err;
    }

    for (;;) {
        switch (s_read_byte_or_zero(parser)) {
        case '\0':
            return AH_EEOF;

        case '"':
            return AH_ENONE;

        case '\\':
            s_skip_if_char(parser, '"');
            break;

        default:
            // TODO: Validate UTF-8.
            break;
        }

        if (string->length >= AH_JSON_LENGTH_MAX) {
            return AH_EOVERFLOW;
        }

        string->length += 1u;
    }
}

static ah_err_t s_parse_number(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    (void) parent;
    (void) level;

    return AH_ENONE;
}

static ah_err_t s_parse_true(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    if (parser->src_end < &parser->src_off[3u] || memcmp(parser->src_off, "rue", 3u) != 0) {
        return s_report_error(parser, parent, level, dst);
    }

    ah_json_val_t* keyword;
    return s_alloc_value(parser, parent, AH_JSON_TYPE_TRUE, level, dst, &keyword);
}

static ah_err_t s_parse_false(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    if (parser->src_end < &parser->src_off[4u] || memcmp(parser->src_off, "alse", 4u) != 0) {
        return s_report_error(parser, parent, level, dst);
    }

    ah_json_val_t* keyword;
    return s_alloc_value(parser, parent, AH_JSON_TYPE_FALSE, level, dst, &keyword);
}

static ah_err_t s_parse_null(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    if (parser->src_end < &parser->src_off[3u] || memcmp(parser->src_off, "ull", 3u) != 0) {
        return s_report_error(parser, parent, level, dst);
    }

    ah_json_val_t* keyword;
    return s_alloc_value(parser, parent, AH_JSON_TYPE_NULL, level, dst, &keyword);
}

static ah_err_t s_report_error(struct s_parser* parser, ah_json_val_t* parent, uint16_t level, ah_json_buf_t* dst)
{
    ah_assert_if_debug(parser != NULL);
    ah_assert_if_debug(dst != NULL);

    ah_json_val_t* val;

    ah_err_t err = s_alloc_value(parser, parent, AH_JSON_TYPE_ERROR, level, dst, &val);
    if (err != AH_ENONE) {
        return err;
    }

    val->length = 1u;

    return AH_EILSEQ;
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
            if (ah_add_size(dst->capacity, dst->capacity / 2u, &new_capacity_in_values) != AH_ENONE) {
                return AH_ENOMEM;
            }
        }

        size_t new_capacity_in_bytes;
        if (ah_mul_size(new_capacity_in_values, sizeof(ah_json_val_t), &new_capacity_in_bytes) != AH_ENONE) {
            return AH_ENOMEM;
        }

        ah_json_val_t* new_values = realloc(dst->values, new_capacity_in_bytes);
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

static uint8_t s_read_byte_or_zero(struct s_parser* parser)
{
    ah_assert_if_debug(parser != NULL);

    if (parser->src_off == parser->src_end) {
        return '\0';
    }

    uint8_t byte = *parser->src_off;
    parser->src_off = &parser->src_off[1u];
    return byte;
}

static void s_skip_byte(struct s_parser* parser)
{
    if (parser->src_off == parser->src_end) {
        return;
    }

    parser->src_off = &parser->src_off[1u];
}

static void s_skip_if_char(struct s_parser* parser, char ch)
{
    ah_assert_if_debug(parser != NULL);

    if (parser->src_off == parser->src_end) {
        return;
    }

    if (parser->src_off[0u] == ch) {
        parser->src_off = &parser->src_off[1u];
    }
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
