// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_PALLOC_H_
#define AH_PALLOC_H_

#include "defs.h"
#include "internal/_palloc.h"

#include <stddef.h>

struct ah_palloc_vtab {
    ah_err_t (*init)(ah_palloc_t* palloc);
    ah_err_t (*alloc)(ah_palloc_t* palloc, void** page);
    ah_err_t (*free)(ah_palloc_t* palloc, void* page);
    ah_err_t (*term)(ah_palloc_t* palloc);
};

struct ah_palloc {
    AH_I_PALLOC_FIELDS
};

ah_extern ah_err_t ah_palloc_init(ah_palloc_t* palloc, const ah_palloc_vtab_t* vtab, size_t page_size);
ah_extern ah_err_t ah_palloc_init_with_defaults(ah_palloc_t* palloc);
ah_extern ah_err_t ah_palloc_alloc(ah_palloc_t* palloc, void** page);
ah_extern ah_err_t ah_palloc_free(ah_palloc_t* palloc, void* page);
ah_extern size_t ah_palloc_get_page_size(const ah_palloc_t* palloc);
ah_extern void* ah_palloc_get_user_data(const ah_palloc_t* palloc);
ah_extern ah_err_t ah_palloc_term(ah_palloc_t* palloc);

#endif
