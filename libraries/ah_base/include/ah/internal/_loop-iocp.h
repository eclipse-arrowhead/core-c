// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_LOOP_H_
#define AH_INTERNAL_IOCP_LOOP_H_

#include "../time.h"

#include <stdbool.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winsock2.h>

#define AH_I_LOOP_PLATFORM_FIELDS \
 HANDLE _iocp_handle;             \
 struct ah_i_loop_task_queue _task_queue;

#define AH_I_LOOP_EVT_PLATFORM_FIELDS \
 void (*_cb)(ah_i_loop_evt_t*);       \
 OVERLAPPED _overlapped;              \
 bool _is_canceled;

struct ah_i_loop_task_entry {
    ah_time_t _baseline;
    struct ah_task* _task;
};

struct ah_i_loop_task_queue {
    size_t _capacity;
    size_t _length;
    struct ah_i_loop_task_entry* _entries;
};

struct ah_i_loop_evt;

ah_extern ah_err_t ah_i_loop_schedule_task(ah_loop_t* loop, ah_time_t baseline, ah_task_t* task);
ah_extern bool ah_i_loop_try_cancel_task(ah_loop_t* loop, ah_task_t* task);

ah_extern ah_err_t ah_i_loop_evt_get_wsa_result(struct ah_i_loop_evt* evt, SOCKET fd, DWORD* n_bytes_transferred);

#endif
