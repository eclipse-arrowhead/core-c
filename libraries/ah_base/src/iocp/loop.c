// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/loop.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <stdlib.h>

ah_extern ah_err_t ah_i_loop_init(ah_loop_t* loop, ah_loop_opts_t* opts)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(opts != NULL);

    if (opts->alloc_cb == NULL) {
        opts->alloc_cb = realloc;
    }

    if (opts->capacity == 0u) {
        opts->capacity = 1024u;
    }

    WSADATA wsa_data;
    int res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (res != 0) {
        return res;
    }

    HANDLE iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    if (iocp_handle == NULL) {
        return GetLastError();
    }

    // TODO: Anything else to setup?

    loop->_iocp_handle = iocp_handle;

    return AH_ENONE;
}

ah_err_t ah_i_loop_poll_no_longer_than_until(ah_loop_t* loop, struct ah_time* time)
{
    ah_assert_if_debug(loop != NULL);

    ah_err_t err = ah_i_loop_get_pending_err(loop);
    if (err != AH_ENONE) {
        return err;
    }

    loop->_now = ah_time_now();

    DWORD timeout_in_ms = 0u; // TODO: time?
    (void) time;

    OVERLAPPED_ENTRY entries[32u];

    ULONG num_entries_removed;
    if (!GetQueuedCompletionStatusEx(loop->_iocp_handle, entries, 32u, &num_entries_removed, timeout_in_ms, false)) {
        return GetLastError();
    }

    loop->_now = ah_time_now();

    for (ULONG i = 0u; i < num_entries_removed; i += 1u) {
        OVERLAPPED_ENTRY* overlapped_entry = &entries[i];
        ah_i_loop_evt_t* evt = CONTAINING_RECORD(overlapped_entry->lpOverlapped, ah_i_loop_evt_t, _overlapped);

        if (ah_likely(evt->_cb != NULL)) {
            evt->_cb(evt, overlapped_entry);
        }

        ah_i_loop_dealloc_evt(loop, evt);
    }

    return AH_EOPNOTSUPP; // TODO: Complete.
}

ah_extern void ah_i_loop_term(ah_loop_t* loop)
{
    ah_assert_if_debug(loop != NULL);

    (void) CloseHandle(loop->_iocp_handle);
    (void) WSACleanup();
}
