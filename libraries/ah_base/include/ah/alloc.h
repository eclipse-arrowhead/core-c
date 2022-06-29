// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ALLOC_H_
#define AH_ALLOC_H_

#include "conf.h"

#define AH_PSIZE     AH_CONF_PSIZE

#define ah_calloc(n, size) AH_CONF_CALLOC((n), (size))
#define ah_free(ptr)       AH_CONF_FREE((ptr))
#define ah_malloc(size)    AH_CONF_MALLOC((size))
#define ah_palloc()        AH_CONF_PALLOC()
#define ah_pfree(page)     AH_CONF_PFREE((page))

#endif
