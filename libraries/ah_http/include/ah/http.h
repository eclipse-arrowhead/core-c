// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include <ah/buf.h>
#include <ah/defs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AH_HTTP_IREQ_ERR_ASTERISK_FORM_WITHOUT_OPTIONS  1u
#define AH_HTTP_IREQ_ERR_AUTHORITY_FORM_WITHOUT_CONNECT 2u
#define AH_HTTP_IREQ_ERR_CONTENT_LENGTH_RESPECIFIED     3u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_LARGE              4u
#define AH_HTTP_IREQ_ERR_HOST_NOT_SPECIFIED             5u
#define AH_HTTP_IREQ_ERR_HOST_RESPECIFIED               6u
#define AH_HTTP_IREQ_ERR_REQUEST_LINE_TOO_LONG          7u
#define AH_HTTP_IREQ_ERR_UNEXPECTED_BODY                8u
#define AH_HTTP_IREQ_ERR_VERSION_NOT_SUPPORTED          9u

#define AH_HTTP_IRES_ERR_HEADERS_TOO_LARGE     1u
#define AH_HTTP_IRES_ERR_STATUS_LINE_TOO_LONG  2u
#define AH_HTTP_IRES_ERR_UNEXPECTED_BODY       3u
#define AH_HTTP_IRES_ERR_VERSION_NOT_SUPPORTED 4u

typedef uint16_t ah_http_ireq_err_t;
typedef uint16_t ah_http_ires_err_t;

typedef struct ah_http_client ah_http_client_t;
typedef struct ah_http_server ah_http_server_t;

typedef struct ah_http_ireq ah_http_ireq_t;
typedef struct ah_http_ireq_cbs ah_http_ireq_cbs_t;
typedef struct ah_http_ires ah_http_ires_t;
typedef struct ah_http_ires_cbs ah_http_ires_cbs_t;
typedef struct ah_http_oreq ah_http_oreq_t;
typedef struct ah_http_ores ah_http_ores_t;
typedef struct ah_http_parser ah_http_parser_t;
typedef struct ah_http_ver ah_http_ver_t;

struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_ireq {
    char* method;    // "GET", "PUT", "POST", "DELETE", or any other HTTP token.
    char* scheme;    // "http" or "https"; may be other value if authority-form.
    char* authority; // NULL unless authority-form.
    char* path;      // Leading '/' always omitted. NULL if authority-form; "*" if asterisk-form.
    char* query;     // Leading '?' always omitted. NULL if none.
    ah_http_ver_t version;

    void* user_data;
};

// `bool` return values indicate if incoming request processing is done. `res`
// is not submitted to
// Any trailer-part headers are provided to `on_header` after last `on_body` and before `on_end`.
struct ah_http_ireq_cbs {
    void (*on_req_line)(ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_header)(ah_http_ireq_t* req, const char* name, const char* val, ah_http_ores_t* res);
    void (*on_headers_end)(ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_body)(ah_http_ireq_t* req, ah_bufvec_t bufvec, ah_http_ores_t* res);
    void (*on_end)(ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_err)(ah_http_ireq_t* req, uint16_t stat, ah_http_ireq_err_t ireq_err, ah_http_ores_t* res);
};

struct ah_http_ires {
    ah_http_ver_t version;
    uint16_t code;
    char* reason; // NULL if none.

    void* user_data;
};

struct ah_http_ires_cbs {
    bool (*on_stat_line)(ah_http_ires_t* res);
    bool (*on_header)(ah_http_ires_t* res, const char* name, const char* val);
    bool (*on_headers_end)(ah_http_ires_t* res);
    bool (*on_body)(ah_http_ires_t* res, ah_bufvec_t bufvec, size_t rem);
    void (*on_end)(ah_http_ires_t* res);
    void (*on_err)(ah_http_ires_t* res, ah_http_ires_err_t ires_err);
};

struct ah_http_oreq {
    const char* method;    // "GET", "PUT", "POST", "DELETE", or any other HTTP token.
    const char* scheme;    // "http" or "https"; may be other value if authority-form.
    const char* authority; // NULL unless authority-form.
    const char* path;      // Leading '/' always omitted. NULL if authority-form; "*" if asterisk-form.
    const char* query;     // Leading '?' always omitted. NULL if none.
    ah_http_ver_t version;
    const char** headers; // Pointer to array of interleaved names and values, terminated by NULL.

    void* user_data;
};

struct ah_http_ores {
    ah_http_ver_t version;
    uint16_t status;
    const char* reason;   // NULL if none.
    const char** headers; // Pointer to array of interleaved names and values, terminated by NULL.

    void* user_data;
};

ah_extern ah_err_t ah_http_request(ah_http_client_t* client, const ah_http_oreq_t* req, ah_bufvec_t body);
ah_extern ah_err_t ah_http_respond(ah_http_server_t* server, const ah_http_ores_t* res, ah_bufvec_t body);

#endif
