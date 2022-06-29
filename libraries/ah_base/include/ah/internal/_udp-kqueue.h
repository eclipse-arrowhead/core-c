// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_KQUEUE_UDP_H_
#define AH_INTERNAL_KQUEUE_UDP_H_

#include "collections/list.h"

#define AH_I_UDP_IN_PLATFORM_FIELDS

#define AH_I_UDP_OUT_PLATFORM_FIELDS \
 struct ah_i_list_entry _list_entry; \
 struct msghdr _msghdr;

#define AH_I_UDP_SOCK_PLATFORM_FIELDS \
 int _fd;                             \
 struct ah_i_list _out_queue;

#endif
