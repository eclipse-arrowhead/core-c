// SPDX-License-Identifier: EPL-2.0

#ifndef AH_C_SERVICE_DISCOVERY_H_
#define AH_C_SERVICE_DISCOVERY_H_

#include "ah-c/internal/_service-discovery.h"

/**
 * @file
 * Consumer utilities for the Service Discovery service.
 */

typedef struct ah_c_service_discovery ah_c_service_discovery_t;
typedef struct ah_c_service_discovery_cbs ah_c_service_discovery_cbs_t;
typedef struct ah_c_service_discovery_obs ah_c_service_discovery_obs_t;
typedef struct ah_c_service_discovery_query_form ah_c_service_discovery_query_form_t;
typedef struct ah_c_service_discovery_query_list ah_c_service_discovery_query_list_t;
typedef struct ah_c_service_discovery_registry_entry ah_c_service_discovery_registry_entry_t;
typedef struct ah_c_service_discovery_registry_entry_id ah_c_service_discovery_registry_entry_id_t;

struct ah_c_service_discovery_cbs {
    void (*on_query)(void* ctx, ah_c_service_discovery_t* cns, ah_c_service_discovery_query_list_t* query_list, ah_err_t err);
    void (*on_register)(void* ctx, ah_c_service_discovery_t* cns, ah_c_service_discovery_registry_entry_t* registry_entry, ah_err_t err);
    void (*on_unregister)(void* ctx, ah_c_service_discovery_t* cns, ah_err_t err);
};

struct ah_c_service_discovery_obs {
    const ah_c_service_discovery_cbs_t* cbs;
    void* ctx;
};

struct ah_c_service_discovery {
    AH_I_C_SERVICE_DISCOVERY_INTERNAL
};

struct ah_c_service_discovery_query_form {
    int x;
};

struct ah_c_service_discovery_query_list {
    int x;
};

struct ah_c_service_discovery_registry_entry {
    int x;
};

struct ah_c_service_discovery_registry_entry_id {
    int x;
};

ah_extern ah_err_t ah_c_service_discovery_query(ah_c_service_discovery_t* cns, const ah_c_service_discovery_query_form_t* form);
ah_extern ah_err_t ah_c_service_discovery_register(ah_c_service_discovery_t* cns, const ah_c_service_discovery_registry_entry_t* entry);
ah_extern ah_err_t ah_c_service_discovery_unregister(ah_c_service_discovery_t* cns, const ah_c_service_discovery_registry_entry_id_t* id);

/**
 * @name Service Discovery Consumer Library Version Details
 * @{
 */

/**
 * Gets human-readable representation of version of this library.
 *
 * @return Constant string representation of version.
 */
ah_extern const char* ah_c_service_discovery_lib_version_str(void);

/**
 * Gets major version of this library.
 *
 * @return Major version indicator.
 */
ah_extern unsigned short ah_c_service_discovery_lib_version_major(void);

/**
 * Gets minor version of this library.
 *
 * @return Minor version indicator.
 */
ah_extern unsigned short ah_c_service_discovery_lib_version_minor(void);

/**
 * Gets patch version of this library.
 *
 * @return Patch version indicator.
 */
ah_extern unsigned short ah_c_service_discovery_lib_version_patch(void);

/** @} */

#endif
