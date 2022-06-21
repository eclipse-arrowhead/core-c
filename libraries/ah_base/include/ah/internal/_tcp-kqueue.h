// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_KQUEUE_TCP_H_
#define AH_INTERNAL_KQUEUE_TCP_H_

#include "collections/list.h"

#define AH_I_TCP_CONN_PLATFORM_FIELDS \
 int _fd;                             \
 struct ah_i_list _out_queue;         \
 struct ah_i_loop_evt* _read_evt;

#define AH_I_TCP_LISTENER_PLATFORM_FIELDS \
 int _fd;                                 \
 struct ah_i_loop_evt* _listen_evt;

#define AH_I_TCP_OUT_PLATFORM_FIELDS \
 struct ah_i_list_entry _list_entry; \
 size_t _buf_offset;

#endif
