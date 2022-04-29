// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_KQUEUE_LOOP_H_
#define AH_INTERNAL_KQUEUE_LOOP_H_

#include "../../defs.h"

#include <sys/event.h>

#define AH_I_LOOP_PLATFORM_FIELDS                                                                                      \
    int _kqueue_fd;                                                                                                    \
    int _kqueue_capacity;                                                                                              \
    int _kqueue_nchanges;                                                                                              \
    struct kevent* _kqueue_changelist;                                                                                 \
    struct kevent* _kqueue_eventlist;

#define AH_I_LOOP_EVT_BODY_TASK_SCHEDULE_AT_PLATFORM_FIELDS
#define AH_I_LOOP_EVT_PLATFORM_FIELDS void (*_cb)(ah_i_loop_evt_t*, struct kevent*);

ah_err_t ah_i_loop_evt_alloc_with_kev(ah_loop_t* loop, ah_i_loop_evt_t** evt, struct kevent** kev);
ah_err_t ah_i_loop_alloc_kev(ah_loop_t* loop, struct kevent** kev);

#endif
