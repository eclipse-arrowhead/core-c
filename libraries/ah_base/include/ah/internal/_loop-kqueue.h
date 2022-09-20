// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_LOOP_KQUEUE_H_
#define AH_INTERNAL_LOOP_KQUEUE_H_

#include "../defs.h"

#include <sys/event.h>

#define AH_I_LOOP_PLATFORM_FIELDS   \
 int _kqueue_fd;                    \
 int _kqueue_capacity;              \
 int _kqueue_nchanges;              \
 struct kevent* _kqueue_changelist; \
 struct kevent* _kqueue_eventlist;

#define AH_I_LOOP_EVT_PLATFORM_FIELDS \
 void (*_cb)(ah_i_loop_evt_t*, struct kevent*);

struct ah_i_loop_evt;

ah_err_t ah_i_loop_evt_alloc_with_kev(ah_loop_t* loop, struct ah_i_loop_evt** evt, struct kevent** kev);
ah_err_t ah_i_loop_alloc_kev(ah_loop_t* loop, struct kevent** kev);

#endif
