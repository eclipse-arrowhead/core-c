// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ALLOC_H_
#define AH_ALLOC_H_

#include "conf.h"

#if AH_CONF_PSIZE < UINT8_MAX
# define AH_I_PSIZE_MAX  UINT8_MAX
# define AH_I_PSIZE_TYPE uint8_t
#elif AH_CONF_PSIZE < UINT16_MAX
# define AH_I_PSIZE_MAX  UINT16_MAX
# define AH_I_PSIZE_TYPE uint16_t
#elif AH_CONF_PSIZE < UINT32_MAX
# define AH_I_PSIZE_MAX  UINT32_MAX
# define AH_I_PSIZE_TYPE uint32_t
#elif AH_CONF_PSIZE < UINT64_MAX
# define AH_I_PSIZE_MAX  UINT64_MAX
# define AH_I_PSIZE_TYPE uint64_t
#else
# error "AH_CONF_PSIZE being set to a value larger than UIN64_MAX is not supported."
#endif

#define AH_PSIZE     AH_CONF_PSIZE
#define AH_PSIZE_MAX AH_I_PSIZE_MAX

typedef AH_I_PSIZE_TYPE ah_psize_t;

#define ah_calloc(n, size) AH_CONF_CALLOC((n), (size))
#define ah_free(ptr)       AH_CONF_FREE((ptr))
#define ah_malloc(size)    AH_CONF_MALLOC((size))
#define ah_palloc()        AH_CONF_PALLOC()
#define ah_pfree(page)     AH_CONF_PFREE((page))

#endif
