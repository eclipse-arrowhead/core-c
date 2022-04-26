// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_HTTP_H_
#define AH_HTTP_H_

#include "internal/http.h"

#include <ah/buf.h>
#include <stdbool.h>
#include <stdint.h>

#define AH_HTTP_IREQ_ERR_ASTERISK_FORM_WITHOUT_OPTIONS  1u
#define AH_HTTP_IREQ_ERR_AUTHORITY_FORM_WITHOUT_CONNECT 2u
#define AH_HTTP_IREQ_ERR_CONTENT_LENGTH_RESPECIFIED     3u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_LARGE              4u
#define AH_HTTP_IREQ_ERR_HEADERS_TOO_MANY               10u
#define AH_HTTP_IREQ_ERR_HOST_NOT_SPECIFIED             5u
#define AH_HTTP_IREQ_ERR_HOST_RESPECIFIED               6u
#define AH_HTTP_IREQ_ERR_REQUEST_LINE_TOO_LONG          7u
#define AH_HTTP_IREQ_ERR_UNEXPECTED_BODY                8u
#define AH_HTTP_IREQ_ERR_VERSION_NOT_SUPPORTED          9u

#define AH_HTTP_IRES_ERR_HEADERS_TOO_LARGE     1u
#define AH_HTTP_IRES_ERR_HEADERS_TOO_MANY      5u
#define AH_HTTP_IRES_ERR_STATUS_LINE_TOO_LONG  2u
#define AH_HTTP_IRES_ERR_UNEXPECTED_BODY       3u
#define AH_HTTP_IRES_ERR_VERSION_NOT_SUPPORTED 4u

typedef uint16_t ah_http_ireq_err_t;
typedef uint16_t ah_http_ires_err_t;

typedef struct ah_http_client ah_http_client_t;
typedef struct ah_http_hmap ah_http_hmap_t;
typedef struct ah_http_hmap_value_iter ah_http_hmap_value_iter_t;
typedef struct ah_http_ireq ah_http_ireq_t;
typedef struct ah_http_server_vtab ah_http_server_vtab_t;
typedef struct ah_http_ires ah_http_ires_t;
typedef struct ah_http_client_vtab ah_http_client_vtab_t;
typedef struct ah_http_header ah_http_header_t;
typedef struct ah_http_hlist ah_http_hlist_t;
typedef struct ah_http_oreq ah_http_oreq_t;
typedef struct ah_http_ores ah_http_ores_t;
typedef struct ah_http_req_line ah_http_req_line_t;
typedef struct ah_http_server ah_http_server_t;
typedef struct ah_http_stat_line ah_http_stat_line_t;
typedef struct ah_http_ver ah_http_ver_t;

struct ah_http_client {
    AH_I_HTTP_CLIENT_FIELDS
};

struct ah_http_client_vtab {
    void (*on_head)(ah_http_client_t* client, ah_http_ires_t* res);
    void (*on_body)(ah_http_client_t* client, ah_http_ires_t* res, ah_bufvec_t bufvec, size_t rem);
    void (*on_done)(ah_http_client_t* client, ah_http_ires_t* res);
    void (*on_err)(ah_http_client_t* client, ah_http_ires_t* res, ah_http_ires_err_t ires_err);
};

struct ah_http_server {
    AH_I_HTTP_SERVER_FIELDS
};

struct ah_http_server_vtab {
    void (*on_head)(ah_http_server_t* server, ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_body)(ah_http_server_t* server, ah_http_ireq_t* req, ah_bufvec_t bufvec, size_t rem, ah_http_ores_t* res);
    void (*on_done)(ah_http_server_t* server, ah_http_ireq_t* req, ah_http_ores_t* res);
    void (*on_err)(ah_http_server_t* server, ah_http_ireq_t* req, ah_http_ireq_err_t cause, ah_http_ores_t* res);
};

struct ah_http_ver {
    uint8_t major;
    uint8_t minor;
};

struct ah_http_req_line {
    char* method;    // "GET", "PUT", "POST", "DELETE", or any other HTTP token.
    char* scheme;    // "http" or "https"; may be other value if authority-form.
    char* authority; // NULL unless authority-form.
    char* path;      // Leading '/' always omitted. NULL if authority-form; "*" if asterisk-form.
    char* query;     // Leading '?' always omitted. NULL if none.
    ah_http_ver_t version;
};

struct ah_http_stat_line {
    ah_http_ver_t version;
    uint16_t code;
    char* reason; // NULL if none.
};

struct ah_http_hmap {
    AH_I_HTTP_HMAP_FIELDS
};

struct ah_http_hmap_value_iter {
    AH_I_HTTP_HMAP_VALUE_ITER_FIELDS
};

struct ah_http_ireq {
    ah_http_req_line_t req_line;
    ah_http_hmap_t headers;
    void* user_data;
};

struct ah_http_ires {
    ah_http_stat_line_t stat_line;
    ah_http_hmap_t headers;
    void* user_data;
};

struct ah_http_header {
    char* name;
    char* value;
};

struct ah_http_hlist {
    ah_http_header_t* pairs; // Array terminated by { NULL, * } pair.
};

struct ah_http_oreq {
    ah_http_req_line_t req_line;
    ah_http_hlist_t headers;
    void* user_data;
};

struct ah_http_ores {
    ah_http_stat_line_t stat_line;
    ah_http_hlist_t headers;
    void* user_data;
};

ah_extern const char* ah_http_hmap_get_value(const ah_http_hmap_t* headers, const char* name, bool* has_next);
ah_extern ah_http_hmap_value_iter_t ah_http_hmap_get_values(const ah_http_hmap_t* headers, const char* name);
ah_extern const char* ah_http_hmap_next_value(ah_http_hmap_value_iter_t* iter);

ah_extern ah_err_t ah_http_request(ah_http_client_t* client, const ah_http_oreq_t* req, ah_bufvec_t body);
ah_extern ah_err_t ah_http_respond(ah_http_server_t* server, const ah_http_ores_t* res, ah_bufvec_t body);

#endif
