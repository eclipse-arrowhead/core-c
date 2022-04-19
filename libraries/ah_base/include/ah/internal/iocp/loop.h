// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_LOOP_H_
#define AH_INTERNAL_IOCP_LOOP_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define AH_I_LOOP_PLATFORM_FIELDS HANDLE _iocp_handle;

#define AH_I_LOOP_EVT_BODY_HAS_TASK_SCHEDULE_AT 1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_CLOSE        0
#define AH_I_LOOP_EVT_BODY_HAS_TCP_CONNECT      1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_LISTEN       1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_OPEN         0
#define AH_I_LOOP_EVT_BODY_HAS_TCP_READ         1
#define AH_I_LOOP_EVT_BODY_HAS_TCP_WRITE        1
#define AH_I_LOOP_EVT_BODY_HAS_UDP_CLOSE        0
#define AH_I_LOOP_EVT_BODY_HAS_UDP_OPEN         0
#define AH_I_LOOP_EVT_BODY_HAS_UDP_RECV         1
#define AH_I_LOOP_EVT_BODY_HAS_UDP_SEND         1

#define AH_I_LOOP_EVT_BODY_TASK_SCHEDULE_AT_PLATFORM_FIELDS

#define AH_I_LOOP_EVT_PLATFORM_FIELDS                                                                                  \
    void (*_cb)(ah_i_loop_evt_t*, OVERLAPPED_ENTRY*);                                                                  \
    OVERLAPPED _overlapped;

#endif
