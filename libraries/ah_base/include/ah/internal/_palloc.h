// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_PALLOC_H_
#define AH_INTERNAL_PALLOC_H_

#define AH_I_PALLOC_FIELDS      \
 const ah_palloc_vtab_t* _vtab; \
 size_t _page_size;             \
 void* _user_data;

#endif
