// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/palloc.h"

#include "ah/assert.h"
#include "ah/conf.h"
#include "ah/err.h"

#include <stdlib.h>

static ah_err_t s_palloc_alloc(ah_palloc_t* palloc, void** page);
static ah_err_t s_palloc_free(ah_palloc_t* palloc, void* page);

static const ah_palloc_vtab_t s_palloc_vtab = {
    .alloc = s_palloc_alloc,
    .free = s_palloc_free,
};

ah_extern ah_err_t ah_palloc_init(ah_palloc_t* palloc, const ah_palloc_vtab_t* vtab, size_t page_size)
{
    if (palloc == NULL || vtab == NULL) {
        return AH_EINVAL;
    }
    if (vtab->alloc == NULL || vtab->free == NULL) {
        return AH_EINVAL;
    }

    *palloc = (ah_palloc_t) {
        ._vtab = vtab,
        ._page_size = page_size == 0u
            ? AH_CONF_PALLOC_DEFAULT_PAGE_SIZE
            : page_size,
    };

    return vtab->init != NULL
        ? vtab->init(palloc)
        : AH_ENONE;
}

ah_extern ah_err_t ah_palloc_init_with_defaults(ah_palloc_t* palloc)
{
    if (palloc == NULL) {
        return AH_EINVAL;
    }

    *palloc = (ah_palloc_t) {
        ._vtab = &s_palloc_vtab,
        ._page_size = AH_CONF_PALLOC_DEFAULT_PAGE_SIZE,
    };

    return AH_ENONE;
}

static ah_err_t s_palloc_alloc(ah_palloc_t* palloc, void** page)
{
    if (palloc == NULL || page == NULL) {
        return AH_EINVAL;
    }

    void* ptr = malloc(palloc->_page_size);
    if (ptr == NULL) {
        return AH_ENOMEM;
    }

    *page = ptr;

    return AH_ENONE;
}

static ah_err_t s_palloc_free(ah_palloc_t* palloc, void* page)
{
    if (palloc == NULL || page == NULL) {
        return AH_EINVAL;
    }

    free(page);

    return AH_ENONE;
}

ah_extern ah_err_t ah_palloc_alloc(ah_palloc_t* palloc, void** page)
{
    if (palloc == NULL) {
        return AH_EINVAL;
    }
    if (palloc->_vtab == NULL || palloc->_vtab->alloc == NULL) {
        return AH_ESTATE;
    }
    return palloc->_vtab->alloc(palloc, page);
}

ah_extern ah_err_t ah_palloc_free(ah_palloc_t* palloc, void* page)
{
    if (palloc == NULL) {
        return AH_EINVAL;
    }
    if (palloc->_vtab == NULL || palloc->_vtab->free == NULL) {
        return AH_ESTATE;
    }
    return palloc->_vtab->free(palloc, page);
}

ah_extern size_t ah_palloc_get_page_size(const ah_palloc_t* palloc)
{
    ah_assert(palloc != NULL);

    return palloc->_page_size;
}

ah_extern void* ah_palloc_get_user_data(const ah_palloc_t* palloc)
{
    ah_assert(palloc != NULL);

    return palloc->_user_data;
}

ah_extern ah_err_t ah_palloc_term(ah_palloc_t* palloc)
{
    if (palloc == NULL) {
        return AH_EINVAL;
    }
    if (palloc->_vtab == NULL) {
        return AH_ESTATE;
    }
    if (palloc->_vtab->term != NULL) {
        palloc->_vtab->term(palloc);
    }
#ifndef NDEBUG
    *palloc = (ah_palloc_t) { 0u };
#endif
    return AH_ENONE;
}
