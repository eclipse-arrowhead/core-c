// SPDX-License-Identifier: EPL-2.0

#ifndef AH_C_SERVICE_DISCOVERY_H_
#define AH_C_SERVICE_DISCOVERY_H_

#include "ah-c/internal/_service-discovery.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Major version of the Service Discovery consumer library, represented by an
 * unsigned integer literal.
 */
#define AH_C_SERVICE_DISCOVERY_VERSION_MAJOR AH_I_C_SERVICE_DISCOVERY_VERSION_MAJOR

/**
 * Minor version of the Service Discovery consumer library, represented by an
 * unsigned integer literal.
 */
#define AH_C_SERVICE_DISCOVERY_VERSION_MINOR AH_I_C_SERVICE_DISCOVERY_VERSION_MINOR

/**
 * Patch version of the Service Discovery consumer library, represented by an
 * unsigned integer literal.
 */
#define AH_C_SERVICE_DISCOVERY_VERSION_PATCH AH_I_C_SERVICE_DISCOVERY_VERSION_PATCH

/**
 * Constant string representation of the Service Discovery consumer library
 * version.
 */
#define AH_C_SERVICE_DISCOVERY_VERSION_STR AH_I_C_SERVICE_DISCOVERY_VERSION_STR

/**
 * @file
 * Consumer utilities for the Service Discovery service.
 */

typedef struct ah_c_service_discovery ah_c_service_discovery_t;
typedef struct ah_c_service_discovery_cbs ah_c_service_discovery_cbs_t;
typedef struct ah_c_service_discovery_entry_id ah_c_service_discovery_entry_id_t;
typedef struct ah_c_service_discovery_entry_req ah_c_service_discovery_entry_req_t;
typedef struct ah_c_service_discovery_entry_res ah_c_service_discovery_entry_res_t;
typedef struct ah_c_service_discovery_impl ah_c_service_discovery_impl_t;
typedef struct ah_c_service_discovery_obs ah_c_service_discovery_obs_t;
typedef struct ah_c_service_discovery_query_req ah_c_service_discovery_query_req_t;
typedef struct ah_c_service_discovery_query_res ah_c_service_discovery_query_res_t;
typedef struct ah_c_service_discovery_vtab ah_c_service_discovery_vtab_t;

struct ah_c_service_discovery_cbs {
    void (*on_query)(void* ctx, ah_c_service_discovery_t* cns, ah_c_service_discovery_query_res_t* query_list, ah_err_t err);
    void (*on_register)(void* ctx, ah_c_service_discovery_t* cns, ah_c_service_discovery_entry_req_t* registry_entry, ah_err_t err);
    void (*on_unregister)(void* ctx, ah_c_service_discovery_t* cns, ah_err_t err);
};

struct ah_c_service_discovery_obs {
    const ah_c_service_discovery_cbs_t* cbs;
    void* ctx;
};

struct ah_c_service_discovery_impl {
    const ah_c_service_discovery_vtab_t* vtab;
    void* ctx;
};

struct ah_c_service_discovery_vtab {
    ah_err_t (*c_query)(ah_c_service_discovery_t* cns, const ah_c_service_discovery_query_req_t* form);
    ah_err_t (*c_register)(ah_c_service_discovery_t* cns, const ah_c_service_discovery_entry_req_t* entry);
    ah_err_t (*c_unregister)(ah_c_service_discovery_t* cns, const ah_c_service_discovery_entry_id_t* id);
};

struct ah_c_service_discovery {
    AH_I_C_SERVICE_DISCOVERY_INTERNAL
};

struct ah_c_service_discovery_entry_id {
    const char* service_definition;
    const char* system_name;
    const char* address;
    uint16_t port;
};

struct ah_c_service_discovery_entry_req {
    char* service_definition;
    struct {
        char* system_name;
        char* address;
        uint16_t port;
        char* authentication_info;
    } provider_system;
    char* service_uri;
    char* end_of_validity;
    char* secure;
    struct {
        char* key;
        char* value;
    } * metadata;
    size_t metadata_length;
    int32_t version;
    char** interfaces;
    size_t interfaces_length;
};

struct ah_c_service_discovery_entry_res {
    int64_t id;
    struct {
        int64_t id;
        char* service_definition;
        char* created_at;
        char* updated_at;
    } service_definition;
    struct {
        int64_t id;
        char* system_name;
        char* address;
        uint16_t port;
        char* authentication_info;
        char* created_at;
        char* updated_at;
    } provider;
    char* service_uri;
    char* end_of_validity;
    char* secure;
    struct {
        char* key;
        char* value;
    } * metadata;
    size_t metadata_length;
    int32_t version;
    struct {
        int64_t id;
        char* interface_name;
        char* created_at;
        char* updated_at;
    } * interfaces;
    size_t interfaces_length;
    char* created_at;
    char* updated_at;
};

struct ah_c_service_discovery_query_req {
    const char* service_definition_requirement;
    const char** interface_requirements;
    size_t interface_requirements_length;
    const char** security_requirements;
    size_t security_requirements_length;
    struct {
        const char* key;
        const char* value;
    } * metadata_requirements;
    size_t metadata_requirements_length;
    int32_t version_requirement;
    int32_t max_version_requirement;
    int32_t min_version_requirement;
    bool ping_providers;
};

struct ah_c_service_discovery_query_res {
    ah_c_service_discovery_entry_res_t* service_query_data;
    size_t service_query_data_length;
    int32_t unfiltered_hits;
};

struct ah_http_client;

ah_extern ah_err_t ah_c_service_discovery_impl_http_json(ah_c_service_discovery_impl_t* impl, struct ah_http_client* http_client);

ah_extern ah_err_t ah_c_service_discovery_init(ah_c_service_discovery_t* cns, ah_c_service_discovery_impl_t impl);
ah_extern ah_err_t ah_c_service_discovery_query(ah_c_service_discovery_t* cns, const ah_c_service_discovery_query_req_t* form);
ah_extern ah_err_t ah_c_service_discovery_register(ah_c_service_discovery_t* cns, const ah_c_service_discovery_entry_req_t* entry);
ah_extern ah_err_t ah_c_service_discovery_unregister(ah_c_service_discovery_t* cns, const ah_c_service_discovery_entry_id_t* id);
ah_extern ah_err_t ah_c_service_discovery_term(ah_c_service_discovery_t* cns);

ah_extern void ah_c_service_discovery_entry_res_free(ah_c_service_discovery_entry_res_t* entry);
ah_extern void ah_c_service_discovery_query_res_free(ah_c_service_discovery_query_res_t* entry);

#endif
